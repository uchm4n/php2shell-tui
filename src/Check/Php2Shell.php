<?php

declare(strict_types=1);

namespace Php2ShellTui\Check;

use Php2ShellTui\Data\Reproduce;
use Php2ShellTui\Finding;
use Php2ShellTui\Http\Client;
use Php2ShellTui\Poc\GuessPlan;
use Php2ShellTui\Poc\Php2ShellPoc;
use Php2ShellTui\Poc\PocResult;
use Php2ShellTui\Poc\Profile;
use Php2ShellTui\Severity;
use Php2ShellTui\Target;
use Psr\Http\Message\ResponseInterface;

final class Php2Shell implements Check, ProgressAware
{
    private ?\Closure $onProgress = null;
    private ?\Closure $onTick = null;

    public function __construct(
        private readonly Reproduce $reproduce,
        private readonly bool $verify,
        private readonly ?Php2ShellPoc $poc = null,
        private readonly ?string $pocDir = null,
        private readonly ?GuessPlan $guess = null,
        private readonly ?Client $client = null,
        private readonly ?\Closure $runner = null,
        private readonly ?int $workers = null,
    ) {
    }

    public function id(): string
    {
        return 'php2shell';
    }

    public function paths(Target $target, ?ResponseInterface $baseline): array
    {
        return [];
    }

    public function setProgress(?callable $onProgress, ?callable $onTick): void
    {
        $this->onProgress = $onProgress === null ? null : \Closure::fromCallable($onProgress);
        $this->onTick = $onTick === null ? null : \Closure::fromCallable($onTick);
    }

    public function analyze(Target $target, array $responses): array
    {
        if (!$this->verify) {
            return [];
        }

        if ($target->pocProfile !== null) {
            return $this->analyzeSingle($target);
        }

        if ($this->guess === null) {
            return [];
        }

        return $this->analyzeGuess($target);
    }

    private function analyzeSingle(Target $target): array
    {
        if ($this->poc === null) {
            return [$this->pocInconclusive($target, 'proof runner is not configured')];
        }

        try {
            $profile = $this->loadProfile((string) $target->pocProfile);
        } catch (\Throwable $e) {
            return [$this->pocInconclusive($target, 'profile is invalid: ' . $e->getMessage())];
        }

        if ($profile === null) {
            return [$this->pocInconclusive($target, 'poc_profile was not found')];
        }

        $this->reportVerify($target, 1, 1);
        $result = $this->poc->run($target, $profile, false, $this->workers, null, $this->onTick);

        if (!$result->confirmed) {
            return [$this->pocInconclusive($target, $result->reason)];
        }

        return [$this->rceFinding($target, $profile, $result)];
    }

    private function analyzeGuess(Target $target): array
    {
        if ($this->poc === null) {
            return [$this->pocInconclusive($target, 'proof runner is not configured')];
        }

        $started = microtime(true);
        $tried = 0;
        $log = [];
        $planned = max(1, min(count($this->guess->profiles), $this->guess->maxAttempts));

        foreach ($this->guess->profiles as $id) {
            $elapsed = microtime(true) - $started;

            if ($tried >= $this->guess->maxAttempts) {
                $log[] = $id . ': skipped (attempt cap)';
                break;
            }

            if ($elapsed >= $this->guess->totalTimeout) {
                $log[] = $id . ': skipped (total timeout)';
                break;
            }

            try {
                $profile = $this->loadProfile($id);
            } catch (\Throwable $e) {
                $log[] = $id . ': invalid profile: ' . $e->getMessage();
                continue;
            }

            if ($profile === null) {
                $log[] = $id . ': profile not found';
                continue;
            }

            if ($this->guess->arch !== null && $profile->arch() !== $this->guess->arch) {
                $log[] = sprintf('%s: skipped (%s profile, configured %s)', $id, $profile->arch(), $this->guess->arch);
                continue;
            }

            $this->reportVerify($target, $tried + 1, $planned);
            $tried++;
            $remaining = max(1, (int) ceil($this->guess->totalTimeout - $elapsed));

            try {
                $result = $this->runner !== null
                    ? ($this->runner)($target, $profile, $this->guess->workers, $remaining)
                    : $this->poc->run($target, $profile, true, $this->guess->workers, $remaining, $this->onTick);
            } catch (\Throwable $e) {
                $log[] = $profile->id() . ': runner failed: ' . $e->getMessage();
                break;
            }

            if ($result->confirmed) {
                return [$this->rceFinding($target, $profile, $result)];
            }

            $log[] = $profile->id() . ': ' . $result->reason . ($result->terminal ? ' [stopped]' : '');

            if ($result->terminal) {
                break;
            }

            if ($this->client !== null) {
                $health = $this->client->get($target->url, $target->requestHeaders());

                if ($health === null || $health->getStatusCode() >= 500) {
                    $log[] = 'target stopped responding; remaining profiles skipped';
                    break;
                }
            }
        }

        if ($tried === 0) {
            return [$this->pocInconclusive(
                $target,
                'no profile was attempted: ' . ($log === [] ? 'empty profile list' : implode('; ', $log)),
            )];
        }

        return [$this->pocInconclusive(
            $target,
            sprintf('tried %d profile(s): %s', $tried, implode('; ', $log)),
        )];
    }

    private function reportVerify(Target $target, int $done, int $total): void
    {
        if ($this->onProgress !== null) {
            ($this->onProgress)($target->label(), 'verify', $done, $total);
        }
    }

    private function loadProfile(string $id): ?Profile
    {
        if (is_file($id)) {
            return Profile::fromFile($id);
        }

        if ($this->pocDir !== null) {
            $path = rtrim($this->pocDir, '/') . '/' . basename($id) . '.json';

            if (is_file($path)) {
                return Profile::fromFile($path);
            }
        }

        return null;
    }

    private function pocInconclusive(Target $target, string $reason): Finding
    {
        return new Finding(
            id: 'php2shell-poc-inconclusive',
            title: 'PHP2Shell - RCE proof not obtained',
            severity: Severity::Info,
            target: $target->label(),
            evidence: 'RCE proof not obtained: ' . $reason,
            exploit: 'No exploit confirmed; do not treat this as safe.',
            reproduce: $this->reproduce->steps('php2shell-rce', $target->url, $target->label()),
        );
    }

    private function rceFinding(Target $target, Profile $profile, PocResult $result): Finding
    {
        return new Finding(
            id: 'php2shell-rce',
            title: 'PHP2Shell - RCE confirmed',
            severity: Severity::Critical,
            target: $target->label(),
            evidence: sprintf(
                'Profile %s; the unique proof marker "%s" was fetched from %s.',
                $profile->id(),
                (string) $result->proof,
                $result->proofPath ?? 'the proof path',
            ),
            exploit: 'The target executed a unique command; this is confirmed remote code execution.',
            reproduce: $this->reproduce->steps('php2shell-rce', $target->url, $target->label()),
        );
    }
}
