<?php

declare(strict_types=1);

namespace Php2ShellTui;

final class PhpVersionAssessment
{
    /**
     * How the advisory reads one advertised version. The severity doubles as
     * the ranking: the worst candidate wins when a target advertises several.
     *
     * @return array{state: string, severity: Severity}
     */
    public static function classify(PhpVersionDb $db, string $version): array
    {
        if ($db->isPrerelease($version)) {
            // A pre-release is never evidence of a stable fix.
            return ['state' => 'prerelease', 'severity' => Severity::High];
        }

        $normalized = $db->normalize($version);

        if ($normalized === null) {
            return ['state' => 'unknown', 'severity' => Severity::High];
        }

        if (version_compare($normalized, $db->newestKnown(), '>')) {
            return ['state' => 'newer', 'severity' => Severity::Low];
        }

        if ($db->isAffected($normalized)) {
            return ['state' => 'affected', 'severity' => Severity::Critical];
        }

        $branch = $db->branch($normalized);

        if ($branch === null
            || $db->vulnerableThrough($branch) === null
            || $db->firstFixed($branch) === null) {
            // Either a branch the advisory does not cover, or an end-of-life
            // branch: only its last release exists and that one is affected, so
            // this version cannot be judged.
            return ['state' => 'unknown', 'severity' => Severity::High];
        }

        return ['state' => 'patched', 'severity' => Severity::Info];
    }
}
