<?php

declare(strict_types=1);

namespace Php2Scan\Check;

use Php2Scan\Finding;
use Php2Scan\Target;
use Psr\Http\Message\ResponseInterface;

interface Check
{
    public function id(): string;

    /**
     * Relative paths this check wants fetched for the given target.
     *
     * @return list<string>
     */
    public function paths(Target $target, ?ResponseInterface $baseline): array;

    /**
     * @param array<string, ResponseInterface> $responses keyed by the requested path
     * @return list<Finding>
     */
    public function analyze(Target $target, array $responses): array;
}
