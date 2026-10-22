<?php

declare(strict_types=1);

namespace Php2ShellTui\Check;

use Php2ShellTui\Finding;
use Php2ShellTui\Target;
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
