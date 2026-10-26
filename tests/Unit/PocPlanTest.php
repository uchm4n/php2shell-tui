<?php

declare(strict_types=1);

namespace Php2ShellTui\Tests\Unit;

use Php2ShellTui\Poc\PocPlan;
use PHPUnit\Framework\TestCase;

final class PocPlanTest extends TestCase
{
    public function testWithMemoryLimitReturnsANewPlan(): void
    {
        $plan = new PocPlan(workers: 150, memoryLimitMb: null);
        $next = $plan->withMemoryLimit(128);

        self::assertNull($plan->memoryLimitMb);
        self::assertSame(128, $next->memoryLimitMb);
        self::assertSame(150, $next->workers);
    }

    public function testItRejectsWorkersAboveTheCap(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new PocPlan(workers: 201, maxWorkers: 200);
    }

    public function testItRejectsNonPositiveTimeouts(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new PocPlan(timeout: 0);
    }
}
