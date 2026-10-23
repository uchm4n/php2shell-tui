<?php

declare(strict_types=1);

namespace Php2ShellTui\Check;

use Php2ShellTui\Data\Reproduce;
use Php2ShellTui\Finding;
use Php2ShellTui\PhpVersionAssessment;
use Php2ShellTui\PhpVersionDb;
use Php2ShellTui\Severity;
use Php2ShellTui\Target;
use Psr\Http\Message\ResponseInterface;

final class PhpVersion implements Check
{
    public function __construct(
        private readonly PhpVersionDb $db,
        private readonly Reproduce $reproduce,
    ) {
    }

    public function id(): string
    {
        return 'php_version';
    }

    public function paths(Target $target, ?ResponseInterface $baseline): array
    {
        return ['/', '/phpinfo.php', '/info.php'];
    }

    /**
     * Every PHP version the target advertises, with where it came from.
     *
     * @param array<string, ResponseInterface> $responses
     * @return list<array{version: string, source: string, confidence: string}>
     */
    private function candidates(array $responses): array
    {
        $candidates = [];

        $baseline = $responses['/'] ?? null;

        if ($baseline !== null) {
            foreach ([['X-Powered-By', 'high'], ['Server', 'medium']] as [$header, $confidence]) {
                $value = $baseline->getHeaderLine($header);
                if ($value === '') {
                    continue;
                }

                if (preg_match_all('/PHP[ \/](\d+\.\d+(?:\.\d+)?[A-Za-z0-9.\-]*)/i', $value, $matches) === false) {
                    continue;
                }

                foreach ($matches[1] as $version) {
                    $candidates[] = ['version' => $version, 'source' => $header, 'confidence' => $confidence];
                }
            }
        }

        foreach (['/phpinfo.php', '/info.php'] as $path) {
            $response = $responses[$path] ?? null;
            if ($response === null || $response->getStatusCode() !== 200) {
                continue;
            }

            $body = (string) $response->getBody();
            if (preg_match('/PHP Version (\d+\.\d+(?:\.\d+)?[A-Za-z0-9.\-]*)/i', $body, $m) === 1) {
                $candidates[] = ['version' => $m[1], 'source' => $path, 'confidence' => 'medium'];
            }
        }

        return $candidates;
    }

    /**
     * @param array{version: string, source: string, confidence: string, state: string, severity: Severity} $candidate
     * @param array{version: string, source: string, confidence: string, state: string, severity: Severity} $other
     */
    private function isWorse(array $candidate, array $other): bool
    {
        if ($candidate['severity'] !== $other['severity']) {
            return $candidate['severity']->rank() > $other['severity']->rank();
        }

        return $candidate['confidence'] === 'high' && $other['confidence'] !== 'high';
    }

    /**
     * @param list<array{version: string, source: string, confidence: string, state: string, severity: Severity}> $candidates
     * @return array{version: string, source: string, confidence: string, state: string, severity: Severity}
     */
    private function worst(array $candidates): array
    {
        $worst = $candidates[0];

        foreach ($candidates as $candidate) {
            if ($this->isWorse($candidate, $worst)) {
                $worst = $candidate;
            }
        }

        return $worst;
    }

    public function analyze(Target $target, array $responses): array
    {
        $steps = $this->reproduce->steps('php2shell-version', $target->url, $target->label());
        $candidates = $this->candidates($responses);

        if ($candidates === []) {
            $baseline = $responses['/'] ?? null;
            $phpPresent = $baseline !== null && PhpDetection::signals($baseline) !== [];

            if (!$phpPresent) {
                return [new Finding(
                    id: 'php2shell-version',
                    title: 'PHP2Shell - no PHP signal detected',
                    severity: Severity::Info,
                    target: $target->label(),
                    evidence: 'No PHP version could be found and no PHP-specific signal fired.',
                    exploit: 'No PHP signal; if PHP runs behind a proxy or hides its headers, verify with server access or a full proof.',
                    reproduce: $steps,
                )];
            }

            return [new Finding(
                id: 'php2shell-version',
                title: 'PHP2Shell - version undetermined',
                severity: Severity::High,
                target: $target->label(),
                evidence: 'PHP is present but the version is not disclosed remotely; the server may still run an affected release. Confirm the package changelog/backport.',
                exploit: 'Read the version with "php -v" and the package changelog on the host - a release before the branch fix (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12) is reported affected; a vendor backport may already be fixed.',
                reproduce: $steps,
            )];
        }

        $ranked = [];
        foreach ($candidates as $candidate) {
            $ranked[] = $candidate + PhpVersionAssessment::classify($this->db, $candidate['version']);
        }

        // Judge on the worst advertised version: an "ok" version in one header
        // must never hide a vulnerable one in another.
        $worst = $this->worst($ranked);

        $version = $worst['version'];
        $source = $worst['source'];
        $confidence = $worst['confidence'];
        $normalized = $this->db->normalize($version) ?? $version;

        [$title, $severity, $evidence, $exploit] = match ($worst['state']) {
            'affected' => [
                'PHP2Shell - ' . implode(' · ', $this->db->cves()),
                Severity::Critical,
                sprintf('PHP %s detected via %s (confidence: %s); affected; %s. Reported affected by upstream version; confirm the package changelog/backport.', $normalized, $source, $confidence, $this->remedy($normalized)),
                'The verified public chain is Apache prefork + mod_php; FPM requires a different, unverified route; a vendor backport may already be fixed.',
            ],
            'patched' => [
                'PHP2Shell not applicable (patched)',
                Severity::Info,
                sprintf('PHP %s detected via %s (confidence: %s); fixed in %s.', $normalized, $source, $confidence, (string) $this->db->fixedFor($normalized)),
                'Nothing to exploit - this runtime is on a patched PHP release.',
            ],
            'newer' => [
                'PHP2Shell - release newer than the advisory',
                Severity::Low,
                sprintf('PHP %s detected via %s (confidence: %s); newer than the newest release the advisory covers (%s).', $normalized, $source, $confidence, $this->db->newestKnown()),
                'Re-check the advisories against this release - the scanner only knows the versions published in the PHP2Shell advisory.',
            ],
            'prerelease' => [
                'PHP2Shell - pre-release build, version undetermined',
                Severity::High,
                sprintf('The server advertised "%s" (via %s), which is a development or pre-release build.', $version, $source),
                'A pre-release is not evidence of a stable fix - check the release the production host actually runs before treating this host as patched.',
            ],
            default => [
                'PHP2Shell - version undetermined',
                Severity::High,
                sprintf('The server advertised "%s" (via %s), which the advisory cannot judge.', $version, $source),
                'Read the version with "php -v" on the host - any release before the branch fixes (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12) is exposed; a vendor backport may already be fixed.',
            ],
        };

        return [new Finding(
            id: 'php2shell-version',
            title: $title,
            severity: $severity,
            target: $target->label(),
            evidence: $evidence,
            exploit: $exploit,
            reproduce: $steps,
        )];
    }

    /**
     * What to do about an affected release.
     */
    private function remedy(string $version): string
    {
        $fixed = $this->db->fixedFor($version);

        if ($fixed !== null) {
            return 'fixed in ' . $fixed;
        }

        return sprintf(
            'this branch has no fixed release, upgrade to %s or newer',
            $this->db->earliestFixed() ?? $this->db->newestKnown(),
        );
    }
}
