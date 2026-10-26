<?php

declare(strict_types=1);

namespace Php2ShellTui\Poc;

final class Profile
{
    /**
     * @param array<string, mixed> $data
     * @param array{zif_system: int, zval_ptr_dtor: int, htdata: int} $libphp
     * @param list<array{0: int, 1: int}> $stage3Pads
     * @param list<int> $memoryLimitTestedMb
     */
    private function __construct(
        private readonly array $data,
        private readonly string $id,
        private readonly string $phpVersion,
        private readonly string $branch,
        private readonly ?string $fixedIn,
        private readonly string $sapi,
        private readonly string $arch,
        private readonly ?string $distro,
        private readonly bool $rceVerified,
        private readonly array $libphp,
        private readonly int $stage1N,
        private readonly int $stage1ForgeLen,
        private readonly int $stage2T,
        private readonly int $stage2V,
        private readonly array $stage3Pads,
        private readonly bool $stage3Carrier,
        private readonly int $oomMb,
        private readonly int $oomMarginMb,
        private readonly array $memoryLimitTestedMb,
        private readonly string $upstreamProfile,
    ) {
    }

    public static function fromFile(string $path): self
    {
        if (!is_file($path) || !is_readable($path)) {
            throw new \InvalidArgumentException(sprintf('Profile "%s" does not exist or is not readable.', $path));
        }

        $raw = file_get_contents($path);
        if ($raw === false) {
            throw new \InvalidArgumentException(sprintf('Cannot read profile "%s".', $path));
        }

        try {
            $data = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new \InvalidArgumentException(sprintf('Profile "%s" is not valid JSON: %s', $path, $e->getMessage()), 0, $e);
        }

        if (!is_array($data) || $data === [] || array_is_list($data)) {
            throw new \InvalidArgumentException(sprintf('Profile "%s" must be a JSON object.', $path));
        }

        return self::fromArray($data);
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $id = self::stringValue($data, 'name', false);
        if ($id === null || $id === '') {
            $id = self::stringValue($data, 'id', false);
        }

        if ($id === null || $id === '') {
            throw new \InvalidArgumentException('Profile field "name" or "id" must be a non-empty string.');
        }

        $phpVersion = self::stringValue($data, 'php_version', true);
        $branch = self::stringValue($data, 'branch', true);
        $sapi = self::stringValue($data, 'sapi', true);
        $arch = self::normalizeArch(self::stringValue($data, 'arch', true) ?? '');
        $fixedIn = self::stringValue($data, 'fixed_in', false);
        $distro = self::normalizeDistro(self::stringValue($data, 'distro', false) ?? self::stringValue($data, 'os', false));
        $verified = self::boolValue($data, 'verified');
        $rce = self::boolValue($data, 'rce');
        $rceVerified = $verified && $rce;
        $upstream = self::stringValue($data, 'upstream_profile', false) ?? 'bookworm';

        $libphpData = self::arrayValue($data, 'libphp');
        $stages = self::arrayValue($data, 'stages');

        $libphp = [
            'zif_system' => self::hexValue($libphpData['zif_system'] ?? null, 'libphp.zif_system', $rceVerified),
            'zval_ptr_dtor' => self::hexValue($libphpData['zval_ptr_dtor'] ?? null, 'libphp.zval_ptr_dtor', $rceVerified),
            'htdata' => self::hexValue($libphpData['htdata'] ?? null, 'libphp.htdata', $rceVerified),
        ];

        $stage1N = self::intValue($stages['stage1_n'] ?? null, 'stages.stage1_n', $rceVerified);
        $stage1ForgeLen = self::intValue($stages['stage1_forge_len'] ?? null, 'stages.stage1_forge_len', $rceVerified);
        $stage2T = self::intValue($stages['stage2_t'] ?? null, 'stages.stage2_t', $rceVerified);
        $stage2V = self::intValue($stages['stage2_v'] ?? null, 'stages.stage2_v', $rceVerified);
        $stage3Pads = self::pads($stages['stage3_pads'] ?? null, $rceVerified);
        $stage3Carrier = self::boolValue($stages, 'stage3_carrier', $rceVerified);

        $oomMb = self::optionalPositiveInt($data, 'oom_mb', 12);
        $oomMarginMb = self::optionalPositiveInt($data, 'oom_margin_mb', 12);

        $tested = [];
        if (isset($data['memory_limit_tested_mb'])) {
            if (!is_array($data['memory_limit_tested_mb'])) {
                throw new \InvalidArgumentException('Profile field "memory_limit_tested_mb" must be a list of integers.');
            }

            foreach ($data['memory_limit_tested_mb'] as $value) {
                if (!is_int($value) || $value < 1) {
                    throw new \InvalidArgumentException('Profile field "memory_limit_tested_mb" must be a list of positive integers.');
                }
                $tested[] = $value;
            }
        }

        return new self(
            data: $data,
            id: $id,
            phpVersion: $phpVersion ?? '',
            branch: $branch ?? '',
            fixedIn: $fixedIn,
            sapi: $sapi ?? '',
            arch: $arch,
            distro: $distro,
            rceVerified: $rceVerified,
            libphp: $libphp,
            stage1N: $stage1N,
            stage1ForgeLen: $stage1ForgeLen,
            stage2T: $stage2T,
            stage2V: $stage2V,
            stage3Pads: $stage3Pads,
            stage3Carrier: $stage3Carrier,
            oomMb: $oomMb,
            oomMarginMb: $oomMarginMb,
            memoryLimitTestedMb: $tested,
            upstreamProfile: $upstream,
        );
    }

    public function id(): string
    {
        return $this->id;
    }

    public function phpVersion(): string
    {
        return $this->phpVersion;
    }

    public function branch(): string
    {
        return $this->branch;
    }

    public function fixedIn(): ?string
    {
        return $this->fixedIn;
    }

    public function sapi(): string
    {
        return $this->sapi;
    }

    public function arch(): string
    {
        return $this->arch;
    }

    public function distro(): ?string
    {
        return $this->distro;
    }

    public function rceVerified(): bool
    {
        return $this->rceVerified;
    }

    /**
     * @return array{zif_system: int, zval_ptr_dtor: int, htdata: int}
     */
    public function libphp(): array
    {
        return $this->libphp;
    }

    public function stage1N(): int
    {
        return $this->stage1N;
    }

    public function stage1ForgeLen(): int
    {
        return $this->stage1ForgeLen;
    }

    public function stage2T(): int
    {
        return $this->stage2T;
    }

    public function stage2V(): int
    {
        return $this->stage2V;
    }

    /**
     * @return list<array{0: int, 1: int}>
     */
    public function stage3Pads(): array
    {
        return $this->stage3Pads;
    }

    public function stage3Carrier(): bool
    {
        return $this->stage3Carrier;
    }

    public function oomMb(): int
    {
        return $this->oomMb;
    }

    public function oomMarginMb(): int
    {
        return $this->oomMarginMb;
    }

    /**
     * @return list<int>
     */
    public function memoryLimitTestedMb(): array
    {
        return $this->memoryLimitTestedMb;
    }

    public function upstreamProfile(): string
    {
        return $this->upstreamProfile;
    }

    /**
     * @return array<string, mixed>
     */
    public function data(): array
    {
        return $this->data;
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function stringValue(array $data, string $key, bool $required): ?string
    {
        if (!array_key_exists($key, $data)) {
            if ($required) {
                throw new \InvalidArgumentException(sprintf('Profile field "%s" is required.', $key));
            }

            return null;
        }

        if (!is_string($data[$key]) || trim($data[$key]) === '') {
            throw new \InvalidArgumentException(sprintf('Profile field "%s" must be a non-empty string.', $key));
        }

        return $data[$key];
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function boolValue(array $data, string $key, bool $required = false): bool
    {
        if (!array_key_exists($key, $data)) {
            if ($required) {
                throw new \InvalidArgumentException(sprintf('Profile field "%s" is required.', $key));
            }

            return false;
        }

        if (!is_bool($data[$key])) {
            throw new \InvalidArgumentException(sprintf('Profile field "%s" must be a boolean.', $key));
        }

        return $data[$key];
    }

    /**
     * @param array<string, mixed> $data
     * @return array<string, mixed>
     */
    private static function arrayValue(array $data, string $key): array
    {
        if (!array_key_exists($key, $data) || !is_array($data[$key])) {
            return [];
        }

        return $data[$key];
    }

    private static function intValue(mixed $value, string $field, bool $required): int
    {
        if ($value === null) {
            if ($required) {
                throw new \InvalidArgumentException(sprintf('Profile field "%s" is required for a verified profile.', $field));
            }

            return 0;
        }

        if (is_int($value)) {
            return $value;
        }

        if (is_string($value) && preg_match('/^-?(?:0x[0-9a-f]+|\d+)$/i', trim($value)) === 1) {
            return (int) intval(trim($value), 0);
        }

        throw new \InvalidArgumentException(sprintf('Profile field "%s" must be an integer.', $field));
    }

    private static function hexValue(mixed $value, string $field, bool $required): int
    {
        if ($value === null) {
            if ($required) {
                throw new \InvalidArgumentException(sprintf('Profile field "%s" is required for a verified profile.', $field));
            }

            return 0;
        }

        if (is_int($value)) {
            return $value;
        }

        if (is_string($value) && preg_match('/^0x[0-9a-f]+$/i', trim($value)) === 1) {
            return (int) hexdec(substr(trim($value), 2));
        }

        throw new \InvalidArgumentException(sprintf('Profile field "%s" must be a hexadecimal string or integer.', $field));
    }

    /**
     * @return list<array{0: int, 1: int}>
     */
    private static function pads(mixed $value, bool $required): array
    {
        if ($value === null) {
            if ($required) {
                throw new \InvalidArgumentException('Profile field "stages.stage3_pads" is required for a verified profile.');
            }

            return [];
        }

        if (!is_array($value) || !array_is_list($value)) {
            throw new \InvalidArgumentException('Profile field "stages.stage3_pads" must be a list of pairs.');
        }

        $pads = [];
        foreach ($value as $pair) {
            if (!is_array($pair) || count($pair) !== 2 || !array_is_list($pair)) {
                throw new \InvalidArgumentException('Each stage3 pad must be a pair of integers.');
            }

            $nl = self::intValue($pair[0], 'stages.stage3_pads', true);
            $vl = self::intValue($pair[1], 'stages.stage3_pads', true);
            if ($nl < 0 || $vl < 0) {
                throw new \InvalidArgumentException('Stage3 pads must not be negative.');
            }

            $pads[] = [$nl, $vl];
        }

        return $pads;
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function optionalPositiveInt(array $data, string $key, int $default): int
    {
        if (!array_key_exists($key, $data)) {
            return $default;
        }

        if (!is_int($data[$key]) || $data[$key] < 1) {
            throw new \InvalidArgumentException(sprintf('Profile field "%s" must be a positive integer.', $key));
        }

        return $data[$key];
    }

    private static function normalizeArch(string $arch): string
    {
        return match (strtolower(trim($arch))) {
            'amd64', 'x86_64' => 'amd64',
            'aarch64', 'arm64' => 'aarch64',
            default => throw new \InvalidArgumentException('Profile field "arch" must be amd64/x86_64 or aarch64/arm64.'),
        };
    }

    private static function normalizeDistro(?string $distro): ?string
    {
        if ($distro === null) {
            return null;
        }

        $lower = strtolower($distro);
        foreach (['debian', 'bookworm', 'bullseye', 'buster', 'trixie'] as $token) {
            if (str_contains($lower, $token)) {
                return 'debian';
            }
        }

        foreach (['ubuntu', 'alpine', 'fedora', 'centos', 'rhel', 'red hat', 'amazon linux', 'suse', 'arch linux'] as $token) {
            if (str_contains($lower, $token)) {
                return $token;
            }
        }

        return $lower;
    }
}
