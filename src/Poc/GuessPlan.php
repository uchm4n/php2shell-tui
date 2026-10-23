<?php

declare(strict_types=1);

namespace Php2ShellTui\Poc;

final class GuessPlan
{
    /**
     * @param list<string> $profiles
     */
    public function __construct(
        public readonly array $profiles,
        public readonly ?string $arch = null,
        public readonly ?int $workers = null,
        public readonly int $maxAttempts = 5,
        public readonly int $totalTimeout = 300,
    ) {
        if ($profiles === []) {
            throw new \InvalidArgumentException('A guess plan needs at least one profile.');
        }

        if ($arch !== null && !in_array($arch, ['amd64', 'aarch64'], true)) {
            throw new \InvalidArgumentException('A guess plan architecture must be amd64 or aarch64.');
        }

        if ($workers !== null && $workers < 1) {
            throw new \InvalidArgumentException('A guess plan worker count must be positive.');
        }

        if ($maxAttempts < 1 || $totalTimeout < 1) {
            throw new \InvalidArgumentException('A guess plan needs positive attempt and timeout limits.');
        }
    }
}
