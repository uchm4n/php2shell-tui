<?php

declare(strict_types=1);

namespace Php2Scan;

final class PhpVersionDb
{
    /**
     * @var array<string, string>
     */
    private readonly array $fixed;

    /**
     * @var list<string>
     */
    private readonly array $cves;

    private readonly string $advisory;

    public function __construct(private readonly string $dataFile)
    {
        $raw = @file_get_contents($dataFile);
        if ($raw === false) {
            throw new \RuntimeException(sprintf('Cannot read the affected-version database "%s".', $dataFile));
        }

        $data = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);

        $this->advisory = (string) ($data['advisory'] ?? 'PHP2Shell');
        $this->fixed = array_map('strval', (array) ($data['fixed'] ?? []));
        $this->cves = array_values(array_map('strval', (array) ($data['cves'] ?? [])));
    }

    public static function fromFile(string $dataFile): self
    {
        return new self($dataFile);
    }

    public function advisoryName(): string
    {
        return $this->advisory;
    }

    public function newestKnown(): string
    {
        $newest = '0.0.0';

        foreach ($this->fixed as $release) {
            if (version_compare($release, $newest, '>')) {
                $newest = $release;
            }
        }

        return $newest;
    }

    /**
     * @return list<string>
     */
    public function cves(): array
    {
        return $this->cves;
    }

    public function firstFixed(string $branch): ?string
    {
        return $this->fixed[$branch] ?? null;
    }

    public function fixedFor(string $version): ?string
    {
        $branch = $this->branch($version);

        return $branch === null ? null : $this->firstFixed($branch);
    }

    public function branch(string $version): ?string
    {
        $normalized = $this->normalize($version);

        if ($normalized === null) {
            return null;
        }

        $parts = explode('.', $normalized);

        return $parts[0] . '.' . $parts[1];
    }

    /**
     * Normalise a raw version string ("PHP/8.2.12", "8.2.12RC1", "8.2.12-1ubuntu2.14",
     * "8.2", "8") to a comparable "major.minor.patch" string, or null when it holds no version.
     */
    public function normalize(string $raw): ?string
    {
        if (preg_match('/(\d+)(?:\.(\d+))?(?:\.(\d+))?/', $raw, $m) !== 1) {
            return null;
        }

        return sprintf('%d.%d.%d', (int) $m[1], (int) ($m[2] ?? 0), (int) ($m[3] ?? 0));
    }

    public function isAffected(string $version): bool
    {
        $normalized = $this->normalize($version);

        if ($normalized === null) {
            return false;
        }

        $branch = $this->branch($normalized);
        if ($branch === null) {
            return false;
        }

        $fixed = $this->firstFixed($branch);

        if ($fixed === null) {
            // No fixed release exists for this branch: it is end-of-life and affected.
            return true;
        }

        return version_compare($normalized, $fixed, '<');
    }
}
