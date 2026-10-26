<?php

declare(strict_types=1);

namespace Php2ShellTui\Check;

use Php2ShellTui\Data\Reproduce;
use Php2ShellTui\Finding;
use Php2ShellTui\Http\Client;
use Php2ShellTui\PhpFingerprint;
use Php2ShellTui\PhpVersionAssessment;
use Php2ShellTui\PhpVersionDb;
use Php2ShellTui\Poc\PocPlan;
use Php2ShellTui\Poc\ProfileCatalog;
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
        private readonly PhpVersionDb $db,
        private readonly ?ProfileCatalog $catalog = null,
        private readonly ?PocPlan $plan = null,
        private readonly ?Client $client = null,
    ) {
    }

    public function id(): string
    {
        return 'php2shell';
    }

    public function paths(Target $target, ?ResponseInterface $baseline): array
    {
        return PhpFingerprint::paths();
    }

    public function setProgress(?callable $onProgress, ?callable $onTick): void
    {
        $this->onProgress = $onProgress === null ? null : \Closure::fromCallable($onProgress);
        $this->onTick = $onTick === null ? null : \Closure::fromCallable($onTick);
    }

    public function analyze(Target $target, array $responses): array
    {
        $fingerprint = PhpFingerprint::fromResponses($responses);
        $findings = [$this->exposureFinding($target, $fingerprint)];

        if (!$this->verify) {
            return $findings;
        }

        if ($this->catalog === null || $this->plan === null) {
            return [...$findings, $this->inconclusive($target, 'verification is not configured')];
        }

        return [...$findings, $this->inconclusive($target, 'verification runner is not wired yet')];
    }

    private function exposureFinding(Target $target, PhpFingerprint $fingerprint): Finding
    {
        $steps = $this->reproduce->steps('php2shell-exposure', $target->url, $target->label());
        $versions = $fingerprint->versions();

        if ($versions === []) {
            if (!$fingerprint->hasPhpSignal()) {
                return new Finding(
                    id: 'php2shell-exposure',
                    title: 'PHP2Shell - no PHP signal detected',
                    severity: Severity::Info,
                    target: $target->label(),
                    evidence: 'No PHP version could be found and no PHP-specific signal fired.',
                    exploit: 'No PHP signal; if PHP runs behind a proxy or hides its headers, verify with server access or a full proof.',
                    reproduce: $steps,
                );
            }

            return new Finding(
                id: 'php2shell-exposure',
                title: 'PHP2Shell - version undetermined',
                severity: Severity::High,
                target: $target->label(),
                evidence: 'PHP is present but the version is not disclosed remotely; the server may still run an affected release. Pass --php-version with the exact build to verify.',
                exploit: 'Read the version with "php -v" on the host - a release before the branch fixes (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12) is affected; a vendor backport may already be fixed.',
                reproduce: $steps,
            );
        }

        $worst = null;
        $worstAssessment = null;

        foreach ($versions as $candidate) {
            $assessment = PhpVersionAssessment::classify($this->db, $candidate['version']);

            if ($worst === null
                || $assessment['severity']->rank() > $worstAssessment['severity']->rank()
                || ($assessment['severity'] === $worstAssessment['severity']
                    && $candidate['confidence'] === 'high'
                    && $worst['confidence'] !== 'high')
            ) {
                $worst = $candidate;
                $worstAssessment = $assessment;
            }
        }

        $version = (string) ($worst['version'] ?? 'unknown');
        $source = (string) ($worst['source'] ?? 'unknown');
        $confidence = (string) ($worst['confidence'] ?? 'low');
        $state = (string) ($worstAssessment['state'] ?? 'unknown');

        if ($state === 'patched') {
            return new Finding(
                id: 'php2shell-exposure',
                title: 'PHP2Shell not applicable (patched)',
                severity: Severity::Info,
                target: $target->label(),
                evidence: sprintf('PHP %s via %s (confidence: %s) is on a patched release; not applicable.', $version, $source, $confidence),
                exploit: 'Nothing to exploit on the known PHP2Shell chain; this runtime is at or above the branch fix.',
                reproduce: $steps,
            );
        }

        if ($state === 'newer') {
            return new Finding(
                id: 'php2shell-exposure',
                title: 'PHP2Shell - release newer than the advisory',
                severity: Severity::Info,
                target: $target->label(),
                evidence: sprintf('PHP %s via %s is newer than the newest release the advisory covers; not judged.', $version, $source),
                exploit: 'Re-check the advisories against this release; the scanner only knows the versions published in the PHP2Shell advisory.',
                reproduce: $steps,
            );
        }

        $ini = $fingerprint->ini();
        $sapi = $fingerprint->sapi();
        $conditions = [];
        $closed = false;

        $sapiStatus = self::sapiStatus($sapi);
        $conditions[] = 'SAPI: ' . ($sapi ?? 'unknown') . ($sapiStatus === 'closed' ? ' (NOT MET)' : '');
        $closed = $closed || $sapiStatus === 'closed';

        foreach ([
            'session.upload_progress.enabled' => ['on', 'session.upload_progress.enabled'],
            'display_errors' => ['on', 'display_errors'],
            'session.use_strict_mode' => ['off', 'session.use_strict_mode'],
        ] as $key => $spec) {
            $status = self::flagStatus($ini[$key] ?? null, $spec[0]);
            if (isset($ini[$key])) {
                $conditions[] = $key . '=' . $ini[$key] . ($status === 'closed' ? ' (NOT MET)' : '');
            } else {
                $conditions[] = $key . '=unknown';
            }
            $closed = $closed || $status === 'closed';
        }

        $memoryLimit = self::sizeToMb($ini['memory_limit'] ?? null);
        if ($memoryLimit === null) {
            $conditions[] = 'memory_limit=unknown';
        } else {
            $conditions[] = 'memory_limit=' . $ini['memory_limit'] . ($memoryLimit === -1 ? ' (NOT MET)' : '');
            $closed = $closed || $memoryLimit === -1;
        }

        $postMax = self::sizeToMb($ini['post_max_size'] ?? null);
        if ($postMax === null) {
            $conditions[] = 'post_max_size=unknown';
        } else {
            $postMaxMet = $postMax <= 0 || ($memoryLimit !== null && $memoryLimit > 0 && $postMax > $memoryLimit + 12);
            $closed = $closed || !$postMaxMet;
            $conditions[] = 'post_max_size=' . $ini['post_max_size'] . ($postMaxMet ? '' : ' (NOT MET)');
        }

        if (isset($ini['upload_max_filesize'])) {
            $conditions[] = 'upload_max_filesize=' . $ini['upload_max_filesize'];
        }

        if (isset($ini['session.use_only_cookies'])) {
            $conditions[] = 'session.use_only_cookies=' . $ini['session.use_only_cookies'];
        }

        if (isset($ini['session.serialize_handler'])) {
            $conditions[] = 'session.serialize_handler=' . $ini['session.serialize_handler'];
        }

        if ($fingerprint->phpinfo() !== null) {
            $conditions[] = 'phpinfo=' . $fingerprint->phpinfo()['url'];
        }

        return new Finding(
            id: 'php2shell-exposure',
            title: 'PHP2Shell - exploitability assessment',
            severity: $closed ? Severity::Medium : Severity::High,
            target: $target->label(),
            evidence: sprintf(
                'PHP %s via %s (confidence: %s). %s.',
                $version,
                $source,
                $confidence,
                implode('; ', $conditions),
            ),
            exploit: 'Run --verify with the calibrated profile to prove RCE; a failed attempt is not evidence of safety.',
            reproduce: $steps,
        );
    }

    private static function sapiStatus(?string $sapi): string
    {
        if ($sapi === null) {
            return 'unknown';
        }

        $lower = strtolower($sapi);

        if (str_contains($lower, 'fpm') || str_contains($lower, 'cgi')) {
            return 'closed';
        }

        return str_contains($lower, 'apache 2.0 handler') || str_contains($lower, 'mod_php')
            ? 'met'
            : 'closed';
    }

    private static function flagStatus(?string $value, string $expected): string
    {
        if ($value === null) {
            return 'unknown';
        }

        $lower = strtolower(trim($value));
        $isOn = in_array($lower, ['1', 'on', 'true', 'yes'], true);
        $isOff = in_array($lower, ['0', 'off', 'false', 'no', ''], true);

        if ($expected === 'on') {
            return $isOn ? 'met' : ($isOff ? 'closed' : 'unknown');
        }

        return $isOff ? 'met' : ($isOn ? 'closed' : 'unknown');
    }

    private static function sizeToMb(?string $raw): ?int
    {
        if ($raw === null || trim($raw) === '') {
            return null;
        }

        $value = strtolower(trim($raw));
        if ($value === '-1') {
            return -1;
        }

        if (preg_match('/^(-?\d+(?:\.\d+)?)([kmgt]?)$/', $value, $matches) !== 1) {
            return null;
        }

        $number = (float) $matches[1];
        $unit = $matches[2] ?? '';

        if ($unit === '') {
            if (abs($number) >= 1048576) {
                return (int) round($number / 1048576);
            }

            return (int) round($number);
        }

        return (int) round($number * match ($unit) {
            'k' => 1 / 1024,
            'm' => 1,
            'g' => 1024,
            't' => 1024 * 1024,
        });
    }

    private function inconclusive(Target $target, string $reason): Finding
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
}
