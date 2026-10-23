<?php

declare(strict_types=1);

namespace Php2ShellTui\Poc;

final class Profile
{
    /**
     * @param array<string, mixed> $data
     * @param array<string, mixed> $offsets
     * @param array<string, mixed> $stages
     */
    private function __construct(
        private readonly array $data,
        private readonly string $id,
        private readonly string $phpVersion,
        private readonly string $sapi,
        private readonly string $arch,
        private readonly int $workers,
        private readonly bool $rceVerified,
        private readonly array $offsets,
        private readonly array $stages,
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
        $id = self::requiredString($data, 'id');
        $phpVersion = self::requiredString($data, 'php_version');
        $sapi = self::requiredString($data, 'sapi');
        $arch = self::normalizeArch(self::requiredString($data, 'arch'));
        $workers = $data['workers'] ?? null;

        if (!is_int($workers) || $workers < 1) {
            throw new \InvalidArgumentException('Profile field "workers" must be a positive integer.');
        }

        $rceVerified = self::optionalBool($data, 'rce_verified');
        $offsets = self::optionalArray($data, 'offsets');
        $stages = self::optionalArray($data, 'stages');

        if ($rceVerified) {
            foreach (['zif_system', 'zval_ptr_dtor'] as $key) {
                if (!array_key_exists($key, $offsets)
                    || (!is_string($offsets[$key]) && !is_int($offsets[$key]))
                    || trim((string) $offsets[$key]) === '') {
                    throw new \InvalidArgumentException(sprintf('Profile field "offsets.%s" is required for a verified profile.', $key));
                }
            }

            foreach ([
                'a1_big',
                'a1_query',
                'b1_fake_len',
                'b1_spec',
                'a2_parts',
                'a2_depth',
                'a2_fillers',
                'b2_vl',
                'b2_n1',
                'b2_n2',
                'carrier_size',
                'main_s_offset',
            ] as $key) {
                if (!array_key_exists($key, $stages)) {
                    throw new \InvalidArgumentException(sprintf('Profile field "stages.%s" is required for a verified profile.', $key));
                }
            }
        }

        return new self(
            data: $data,
            id: $id,
            phpVersion: $phpVersion,
            sapi: $sapi,
            arch: $arch,
            workers: $workers,
            rceVerified: $rceVerified,
            offsets: $offsets,
            stages: $stages,
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

    public function sapi(): string
    {
        return $this->sapi;
    }

    public function arch(): string
    {
        return $this->arch;
    }

    public function workers(): int
    {
        return $this->workers;
    }

    public function rceVerified(): bool
    {
        return $this->rceVerified;
    }

    /**
     * @return array<string, mixed>
     */
    public function offsets(): array
    {
        return $this->offsets;
    }

    /**
     * @return array<string, mixed>
     */
    public function stages(): array
    {
        return $this->stages;
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
    private static function requiredString(array $data, string $key): string
    {
        $value = $data[$key] ?? null;

        if (!is_string($value) || trim($value) === '') {
            throw new \InvalidArgumentException(sprintf('Profile field "%s" must be a non-empty string.', $key));
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $data
     */
    private static function optionalBool(array $data, string $key): bool
    {
        if (!array_key_exists($key, $data)) {
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
    private static function optionalArray(array $data, string $key): array
    {
        if (!array_key_exists($key, $data)) {
            return [];
        }

        if (!is_array($data[$key])) {
            throw new \InvalidArgumentException(sprintf('Profile field "%s" must be an object or array.', $key));
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
}
