<?php

declare(strict_types=1);

namespace Php2ShellTui\Check;

use Php2ShellTui\Data\Reproduce;
use Php2ShellTui\Finding;
use Php2ShellTui\Http\Client;
use Php2ShellTui\PhpFingerprint;
use Php2ShellTui\PhpVersionAssessment;
use Php2ShellTui\PhpVersionDb;
use Php2ShellTui\Poc\Php2ShellPoc;
use Php2ShellTui\Poc\PocPlan;
use Php2ShellTui\Poc\PocResult;
use Php2ShellTui\Poc\Profile;
use Php2ShellTui\Poc\ProfileCatalog;
use Php2ShellTui\ScanCancelled;
use Php2ShellTui\ScanRestart;
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
        private readonly ?Php2ShellPoc $poc = null,
        private readonly ?ProfileCatalog $catalog = null,
        private readonly ?PocPlan $plan = null,
        private readonly ?Client $client = null,
        private readonly ?\Closure $runner = null,
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

        if ($this->poc === null || $this->catalog === null || $this->plan === null) {
            return [...$findings, $this->inconclusive($target, 'verification is not configured')];
        }

        try {
            [$profile, $reason] = $this->selectProfile($target, $fingerprint, $this->plan);
        } catch (\Throwable $e) {
            return [...$findings, $this->inconclusive($target, 'profile is invalid: ' . $e->getMessage())];
        }

        if ($profile === null) {
            return [...$findings, $this->inconclusive($target, $reason)];
        }

        [$runPlan, $reason, $warning] = $this->gate($target, $fingerprint, $profile, $this->plan);

        if ($runPlan === null) {
            return [...$findings, $this->inconclusive($target, $reason)];
        }

        $this->reportVerify($target, 1, 1);

        try {
            $result = $this->runner !== null
                ? ($this->runner)($target, $profile, $runPlan)
                : $this->poc->run($target, $profile, $runPlan, $this->onTick);
        } catch (ScanCancelled|ScanRestart $e) {
            throw $e;
        } catch (\Throwable $e) {
            return [...$findings, $this->inconclusive($target, 'verification failed: ' . $e->getMessage())];
        }

        if (!$result->confirmed) {
            return [...$findings, $this->inconclusive(
                $target,
                $result->reason . ($warning !== null ? '; ' . $warning : ''),
            )];
        }

        return [...$findings, $this->rceFinding($target, $profile, $result, $warning)];
    }

    /**
     * @return array{0: ?Profile, 1: string}
     */
    private function selectProfile(Target $target, PhpFingerprint $fingerprint, PocPlan $plan): array
    {
        $trusted = [];
        $low = [];

        foreach ($fingerprint->versions() as $candidate) {
            if ($candidate['source'] === 'body') {
                $low[$candidate['version']] = true;
            } else {
                $trusted[$candidate['version']] = true;
            }
        }

        $trustedVersions = array_keys($trusted);
        $lowVersions = array_keys($low);

        if (count($trustedVersions) > 1) {
            return [null, sprintf(
                'target advertises conflicting PHP versions (%s); refusing verification until it is unambiguous',
                implode(', ', $trustedVersions),
            )];
        }

        $trustedVersion = $trustedVersions[0] ?? null;
        $explicit = $plan->profile ?? $target->pocProfile;

        if ($explicit !== null) {
            $selection = $this->catalog->select($trustedVersion, $plan->arch, $explicit, $fingerprint->serverOs());

            return [$selection['profile'], $selection['reason']];
        }

        if ($plan->version !== null) {
            if ($trustedVersion !== null && $trustedVersion !== $plan->version) {
                return [null, sprintf(
                    'target advertises PHP %s; refusing the %s override',
                    $trustedVersion,
                    $plan->version,
                )];
            }

            $selection = $this->catalog->select($plan->version, $plan->arch, null, $fingerprint->serverOs());

            return [$selection['profile'], $selection['reason']];
        }

        if ($trustedVersion === null) {
            if ($lowVersions !== []) {
                return [null, sprintf(
                    'only low-confidence PHP version(s) found (%s); pass --php-version X.Y.Z',
                    implode(', ', $lowVersions),
                )];
            }

            return [null, 'PHP version is unknown; pass --php-version X.Y.Z'];
        }

        $selection = $this->catalog->select($trustedVersion, $plan->arch, null, $fingerprint->serverOs());

        return [$selection['profile'], $selection['reason']];
    }

    /**
     * @return array{0: ?PocPlan, 1: string, 2: ?string}
     */
    private function gate(Target $target, PhpFingerprint $fingerprint, Profile $profile, PocPlan $plan): array
    {
        if ($plan->workers === null) {
            return [null, 'workers are not configured; set poc.workers to the target MaxRequestWorkers (1 for a single-worker lab)', null];
        }

        $sapi = $fingerprint->sapi();
        if (self::sapiStatus($sapi) === 'closed') {
            return [null, 'the verified chain is mod_php only' . ($sapi !== null ? ' (SAPI: ' . $sapi . ')' : ''), null];
        }

        $ini = $fingerprint->ini();

        if (self::flagStatus($ini['session.upload_progress.enabled'] ?? null, 'on') === 'closed') {
            return [null, 'session.upload_progress.enabled is off', null];
        }

        if (self::flagStatus($ini['display_errors'] ?? null, 'on') === 'closed') {
            return [null, 'display_errors is off; the parametric chain needs it on', null];
        }

        if (self::flagStatus($ini['session.use_strict_mode'] ?? null, 'off') === 'closed') {
            return [null, 'session.use_strict_mode is on', null];
        }

        $memory = $plan->memoryLimitMb;

        if ($memory === null) {
            $observed = self::sizeToMb($ini['memory_limit'] ?? null);
            if ($observed === -1) {
                return [null, 'memory_limit is unlimited', null];
            }
            if ($observed !== null) {
                $memory = $observed;
            }
        }

        if ($memory === null) {
            $memory = $this->poc?->probeMemoryLimit($target, $plan->requestTimeout);
        }

        $warning = null;

        if ($memory === null) {
            $memory = $profile->oomMb();
            $warning = sprintf(
                'memory_limit was not observable; using the profile default %dM; pass --memory-limit if the chain fails',
                $memory,
            );
        }

        if ($memory < 1) {
            return [null, 'memory_limit is unlimited', null];
        }

        $huge = self::hugeMb($profile, $memory);
        $postMax = self::sizeToMb($ini['post_max_size'] ?? null);

        if ($postMax !== null && $postMax > 0 && $postMax <= $huge) {
            return [null, sprintf('post_max_size is below the required %dM for memory_limit=%dM', $huge, $memory), null];
        }

        return [$plan->withMemoryLimit($memory), '', $warning];
    }

    private function reportVerify(Target $target, int $done, int $total): void
    {
        if ($this->onProgress !== null) {
            ($this->onProgress)($target->label(), 'verify', $done, $total);
        }
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
        $matchingProfile = null;

        if ($this->catalog !== null) {
            try {
                $selection = $this->catalog->select($version, null, null, $fingerprint->serverOs());
                $matchingProfile = $selection['profile'];
            } catch (\Throwable) {
                $matchingProfile = null;
            }
        }

        $conditions[] = 'profile=' . ($matchingProfile?->id() ?? 'none');
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
        } elseif ($memoryLimit === null || $memoryLimit < 1) {
            $conditions[] = 'post_max_size=' . $ini['post_max_size'];
        } else {
            $huge = self::hugeMb($matchingProfile, $memoryLimit);
            $postMaxMet = $postMax <= 0 || $postMax > $huge;
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

        if (str_contains($lower, 'inferred: mod_php')) {
            return 'unknown';
        }

        if (str_contains($lower, 'mod_php') || str_contains($lower, 'apache2handler')) {
            return 'met';
        }

        return str_contains($lower, 'apache') && str_contains($lower, 'handler')
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

    private static function hugeMb(?Profile $profile, int $memoryLimitMb): int
    {
        if ($memoryLimitMb === 8) {
            return $profile?->oomMb() ?? 12;
        }

        return $memoryLimitMb + ($profile?->oomMarginMb() ?? 12);
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

    private function rceFinding(Target $target, Profile $profile, PocResult $result, ?string $warning = null): Finding
    {
        $evidence = sprintf(
            'Profile %s; the unique proof marker "%s" was fetched from %s.',
            $profile->id(),
            (string) $result->proof,
            $result->proofPath ?? 'the proof path',
        );

        if ($result->evidence !== null && $result->evidence !== '') {
            $evidence .= ' Evidence: ' . $result->evidence . '.';
        }

        if ($warning !== null) {
            $evidence .= ' Note: ' . $warning . '.';
        }

        return new Finding(
            id: 'php2shell-rce',
            title: 'PHP2Shell - RCE confirmed',
            severity: Severity::Critical,
            target: $target->label(),
            evidence: $evidence,
            exploit: 'The target executed a unique command; this is confirmed remote code execution.',
            reproduce: $this->reproduce->steps('php2shell-rce', $target->url, $target->label()),
        );
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
