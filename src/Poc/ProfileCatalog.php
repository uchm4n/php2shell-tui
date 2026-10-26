<?php

declare(strict_types=1);

namespace Php2ShellTui\Poc;

final class ProfileCatalog
{
    /**
     * @var null|list<Profile>
     */
    private ?array $profiles = null;

    public function __construct(private readonly string $directory)
    {
    }

    /**
     * @return list<Profile>
     */
    public function all(): array
    {
        if ($this->profiles !== null) {
            return $this->profiles;
        }

        $directory = rtrim($this->directory, '/');
        $entries = @scandir($directory);
        if ($entries === false) {
            throw new \RuntimeException(sprintf('Cannot list the profile directory "%s".', $directory));
        }

        sort($entries);
        $profiles = [];
        foreach ($entries as $entry) {
            if (!str_ends_with($entry, '.json')) {
                continue;
            }

            $profiles[] = Profile::fromFile($directory . '/' . $entry);
        }

        return $this->profiles = $profiles;
    }

    /**
     * @return array{profile: ?Profile, reason: string}
     */
    public function select(?string $version, ?string $arch, ?string $profile, ?string $serverOs): array
    {
        $arch = $this->normalizeArch($arch);
        if ($arch === false) {
            return ['profile' => null, 'reason' => 'arch must be amd64 or aarch64'];
        }

        if ($profile !== null) {
            return $this->selectExplicit($profile, $version, $arch, $serverOs);
        }

        if ($version === null || trim($version) === '') {
            return ['profile' => null, 'reason' => 'no PHP version detected; pass --php-version X.Y.Z'];
        }

        $version = trim($version);
        if (preg_match('/^\d+\.\d+$/', $version) === 1) {
            return [
                'profile' => null,
                'reason' => sprintf(
                    'specify an exact patch release (x.y.z); available: %s',
                    $this->availableVersions(),
                ),
            ];
        }

        $exact = [];
        foreach ($this->all() as $candidate) {
            if ($candidate->phpVersion() === $version && ($arch === null || $candidate->arch() === $arch)) {
                $exact[] = $candidate;
            }
        }

        if ($exact === []) {
            return [
                'profile' => null,
                'reason' => sprintf(
                    'no calibrated profile for PHP %s (%s); available: %s',
                    $version,
                    $arch ?? 'any arch',
                    $this->availableVersions(),
                ),
            ];
        }

        if (count($exact) > 1) {
            return [
                'profile' => null,
                'reason' => sprintf(
                    'multiple builds for PHP %s; pass --arch amd64|aarch64 (%s)',
                    $version,
                    implode(', ', array_map(static fn (Profile $p): string => $p->arch(), $exact)),
                ),
            ];
        }

        $selected = $exact[0];

        if (!$selected->rceVerified()) {
            return ['profile' => null, 'reason' => sprintf('profile %s is not verified for RCE', $selected->id())];
        }

        if ($serverOs !== null && $selected->distro() !== null
            && $this->normalizeOs($serverOs) !== $this->normalizeOs($selected->distro())) {
            return [
                'profile' => null,
                'reason' => sprintf(
                    'target looks like %s, profile %s is for %s',
                    $serverOs,
                    $selected->id(),
                    $selected->distro(),
                ),
            ];
        }

        return ['profile' => $selected, 'reason' => ''];
    }

    /**
     * @return array{profile: ?Profile, reason: string}
     */
    private function selectExplicit(string $profile, ?string $version, ?string $arch, ?string $serverOs): array
    {
        $selected = null;

        if (is_file($profile)) {
            $selected = Profile::fromFile($profile);
        } else {
            $matches = array_values(array_filter(
                $this->all(),
                static fn (Profile $candidate): bool => $candidate->id() === $profile,
            ));

            if (count($matches) === 1) {
                $selected = $matches[0];
            } elseif (count($matches) > 1) {
                return ['profile' => null, 'reason' => sprintf('profile "%s" matches more than one catalog entry', $profile)];
            }
        }

        if ($selected === null) {
            return ['profile' => null, 'reason' => sprintf('no profile matches "%s"', $profile)];
        }

        if (!$selected->rceVerified()) {
            return ['profile' => null, 'reason' => sprintf('profile %s is not verified for RCE', $selected->id())];
        }

        if ($version !== null && $selected->phpVersion() !== $version) {
            return [
                'profile' => null,
                'reason' => sprintf(
                    'profile %s targets PHP %s, requested PHP %s',
                    $selected->id(),
                    $selected->phpVersion(),
                    $version,
                ),
            ];
        }

        if ($arch !== null && $selected->arch() !== $arch) {
            return [
                'profile' => null,
                'reason' => sprintf('profile %s targets %s, requested %s', $selected->id(), $selected->arch(), $arch),
            ];
        }

        if ($serverOs !== null && $selected->distro() !== null
            && $this->normalizeOs($serverOs) !== $this->normalizeOs($selected->distro())) {
            return [
                'profile' => null,
                'reason' => sprintf(
                    'target looks like %s, profile %s is for %s',
                    $serverOs,
                    $selected->id(),
                    $selected->distro(),
                ),
            ];
        }

        return ['profile' => $selected, 'reason' => ''];
    }

    private function availableVersions(): string
    {
        $versions = [];
        foreach ($this->all() as $profile) {
            $versions[] = $profile->phpVersion() . ' ' . $profile->arch();
        }

        return implode(', ', array_values(array_unique($versions)));
    }

    /**
     * @return false|null|string
     */
    private function normalizeArch(?string $arch): false|null|string
    {
        if ($arch === null || trim($arch) === '') {
            return null;
        }

        return match (strtolower(trim($arch))) {
            'amd64', 'x86_64' => 'amd64',
            'aarch64', 'arm64' => 'aarch64',
            default => false,
        };
    }

    private function normalizeOs(string $os): string
    {
        $lower = strtolower($os);

        foreach (['debian', 'bookworm', 'bullseye', 'buster', 'trixie'] as $token) {
            if (str_contains($lower, $token)) {
                return 'debian';
            }
        }

        return $lower;
    }
}
