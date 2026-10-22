<?php

declare(strict_types=1);

namespace Php2Scan;

enum Severity: string
{
    case Critical = 'critical';
    case High = 'high';
    case Medium = 'medium';
    case Low = 'low';
    case Info = 'info';

    public function rank(): int
    {
        return match ($this) {
            self::Critical => 5,
            self::High => 4,
            self::Medium => 3,
            self::Low => 2,
            self::Info => 1,
        };
    }

    public function atLeast(self $min): bool
    {
        return $this->rank() >= $min->rank();
    }

    public static function fromName(string $name): self
    {
        return self::tryFrom(strtolower($name))
            ?? throw new \InvalidArgumentException(sprintf(
                'Unknown severity "%s"; expected one of %s.',
                $name,
                implode(', ', array_column(self::cases(), 'value')),
            ));
    }
}
