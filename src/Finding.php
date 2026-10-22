<?php

declare(strict_types=1);

namespace Php2ShellTui;

final class Finding
{
    /**
     * @param list<string> $reproduce
     */
    public function __construct(
        public readonly string $id,
        public readonly string $title,
        public readonly Severity $severity,
        public readonly string $target,
        public readonly string $evidence,
        public readonly string $exploit,
        public readonly array $reproduce,
    ) {
        if (trim($exploit) === '') {
            throw new \InvalidArgumentException('A finding must carry a non-empty exploit sentence.');
        }
    }
}
