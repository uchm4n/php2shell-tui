<?php

declare(strict_types=1);

namespace Php2ShellTui;

final class ScanResult
{
    /**
     * @param list<Finding>                             $findings
     * @param list<array{target: string, error: string}> $unreachable
     * @param list<array{target: string, status: int}>    $unscannable
     */
    public function __construct(
        public readonly array $findings,
        public readonly array $unreachable,
        public readonly array $unscannable,
        public readonly float $duration,
    ) {
    }
}
