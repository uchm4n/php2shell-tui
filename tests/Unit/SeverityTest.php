<?php

declare(strict_types=1);

namespace Php2Scan\Tests\Unit;

use Php2Scan\Severity;
use PHPUnit\Framework\TestCase;

final class SeverityTest extends TestCase
{
    public function testRankOrdersTheScale(): void
    {
        self::assertSame(5, Severity::Critical->rank());
        self::assertSame(4, Severity::High->rank());
        self::assertSame(3, Severity::Medium->rank());
        self::assertSame(2, Severity::Low->rank());
        self::assertSame(1, Severity::Info->rank());
    }

    public function testAtLeastComparesByRank(): void
    {
        self::assertTrue(Severity::Critical->atLeast(Severity::High));
        self::assertTrue(Severity::High->atLeast(Severity::High));
        self::assertFalse(Severity::Medium->atLeast(Severity::High));
    }

    public function testFromNameAcceptsTheFiveKnownNames(): void
    {
        self::assertSame(Severity::Critical, Severity::fromName('critical'));
        self::assertSame(Severity::Info, Severity::fromName('info'));
    }

    public function testFromNameIsCaseInsensitive(): void
    {
        self::assertSame(Severity::High, Severity::fromName('HIGH'));
        self::assertSame(Severity::Medium, Severity::fromName('Medium'));
    }

    public function testFromNameRejectsAnUnknownName(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Severity::fromName('catastrophic');
    }
}
