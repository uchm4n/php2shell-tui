<?php

declare(strict_types=1);

namespace Php2ShellTui\Report;

use Php2ShellTui\Severity;

final class Theme
{
    public static function symbol(Severity $severity): string
    {
        return match ($severity) {
            Severity::Critical => '!',
            Severity::High => '^',
            Severity::Medium => '-',
            Severity::Low => '.',
            Severity::Info => 'i',
        };
    }

    public static function label(Severity $severity): string
    {
        return strtoupper($severity->value);
    }
}
