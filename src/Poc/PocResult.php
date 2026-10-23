<?php

declare(strict_types=1);

namespace Php2ShellTui\Poc;

final class PocResult
{
    public function __construct(
        public readonly bool $confirmed,
        public readonly string $reason,
        public readonly ?string $proof = null,
        public readonly ?string $evidence = null,
        public readonly ?string $proofPath = null,
        public readonly bool $terminal = false,
    ) {
        if (trim($reason) === '') {
            throw new \InvalidArgumentException('A PoC result must carry a reason.');
        }

        if ($confirmed && ($proof === null || trim($proof) === '')) {
            throw new \InvalidArgumentException('A confirmed PoC result must carry the proof.');
        }
    }
}
