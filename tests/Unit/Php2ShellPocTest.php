<?php

declare(strict_types=1);

namespace Php2ShellTui\Tests\Unit;

use Php2ShellTui\Poc\Php2ShellPoc;
use Php2ShellTui\Poc\PocPlan;
use Php2ShellTui\Poc\Profile;
use Php2ShellTui\Target;
use PHPUnit\Framework\TestCase;

final class Php2ShellPocTest extends TestCase
{
    private function profile(): Profile
    {
        return Profile::fromFile(__DIR__ . '/../../src/Data/poc/php-8.4.26-bookworm-amd64.json');
    }

    /**
     * @return array<string, mixed>
     */
    private function profileData(): array
    {
        return json_decode(
            (string) file_get_contents(__DIR__ . '/../../src/Data/poc/php-8.4.26-bookworm-amd64.json'),
            true,
            512,
            JSON_THROW_ON_ERROR,
        );
    }

    public function testItRefusesAnUnverifiedProfileBeforeSending(): void
    {
        $data = $this->profileData();
        $data['rce'] = false;

        $result = (new Php2ShellPoc())->run(
            new Target('http://127.0.0.1:1/', postPath: '/index.php'),
            Profile::fromArray($data),
            new PocPlan(workers: 1, memoryLimitMb: 8),
        );

        self::assertFalse($result->confirmed);
        self::assertStringContainsString('not verified', $result->reason);
    }

    public function testItRefusesAnFpmProfileBeforeSending(): void
    {
        $data = $this->profileData();
        $data['sapi'] = 'fpm-fcgi';

        $result = (new Php2ShellPoc())->run(
            new Target('http://127.0.0.1:1/', postPath: '/index.php'),
            Profile::fromArray($data),
            new PocPlan(workers: 1, memoryLimitMb: 8),
        );

        self::assertFalse($result->confirmed);
        self::assertStringContainsString('mod_php', $result->reason);
    }

    public function testAWorkerCountAboveTheCapIsRejectedByThePlan(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new PocPlan(workers: 201, maxWorkers: 200);
    }

    public function testItRefusesMissingWorkersAndMemory(): void
    {
        $poc = new Php2ShellPoc();
        $target = new Target('http://127.0.0.1:1/', postPath: '/index.php');

        $noWorkers = $poc->run($target, $this->profile(), new PocPlan(memoryLimitMb: 8));
        self::assertFalse($noWorkers->confirmed);
        self::assertStringContainsString('workers', $noWorkers->reason);

        $noMemory = $poc->run($target, $this->profile(), new PocPlan(workers: 1));
        self::assertFalse($noMemory->confirmed);
        self::assertStringContainsString('memory limit', $noMemory->reason);
    }

    public function testItRefusesAMissingProofClient(): void
    {
        $result = (new Php2ShellPoc())->run(
            new Target('http://127.0.0.1:1/', postPath: '/index.php'),
            $this->profile(),
            new PocPlan(workers: 1, memoryLimitMb: 8),
        );

        self::assertFalse($result->confirmed);
        self::assertStringContainsString('proof client', $result->reason);
    }
}
