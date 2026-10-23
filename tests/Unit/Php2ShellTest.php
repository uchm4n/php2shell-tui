<?php

declare(strict_types=1);

namespace Php2ShellTui\Tests\Unit;

use Php2ShellTui\Check\Php2Shell;
use Php2ShellTui\Data\Reproduce;
use Php2ShellTui\Poc\Php2ShellPoc;
use Php2ShellTui\Severity;
use Php2ShellTui\Target;
use PHPUnit\Framework\TestCase;

final class Php2ShellTest extends TestCase
{
    private Reproduce $reproduce;
    private string $pocDir;

    protected function setUp(): void
    {
        $this->reproduce = new Reproduce(__DIR__ . '/../../src/Data/repro');
        $this->pocDir = __DIR__ . '/../../src/Data/poc';
    }

    public function testItDoesNothingWithoutVerify(): void
    {
        $target = new Target('https://app.example/', pocProfile: 'php-8.4.26-apache-bookworm-amd64');
        $check = new Php2Shell($this->reproduce, false, new Php2ShellPoc(), $this->pocDir);

        self::assertSame([], $check->analyze($target, []));
    }

    public function testItDoesNothingWithoutAProfile(): void
    {
        $check = new Php2Shell($this->reproduce, true, new Php2ShellPoc(), $this->pocDir);

        self::assertSame([], $check->analyze(new Target('https://app.example/'), []));
    }

    public function testItReportsAMissingRunner(): void
    {
        $target = new Target('https://app.example/', pocProfile: 'php-8.4.26-apache-bookworm-amd64');
        $check = new Php2Shell($this->reproduce, true);

        $findings = $check->analyze($target, []);

        self::assertCount(1, $findings);
        self::assertSame('php2shell-poc-inconclusive', $findings[0]->id);
        self::assertSame(Severity::Info, $findings[0]->severity);
        self::assertStringContainsString('runner', $findings[0]->evidence);
    }

    public function testItReportsAMissingProfile(): void
    {
        $target = new Target('https://app.example/', pocProfile: 'no-such-profile');
        $check = new Php2Shell($this->reproduce, true, new Php2ShellPoc(), $this->pocDir);

        $findings = $check->analyze($target, []);

        self::assertCount(1, $findings);
        self::assertSame('php2shell-poc-inconclusive', $findings[0]->id);
        self::assertStringContainsString('poc_profile', $findings[0]->evidence);
    }

    public function testItReportsAnInvalidProfile(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'p2s-bad-profile-');
        self::assertNotFalse($path);
        file_put_contents($path, '{');
        $target = new Target('https://app.example/', pocProfile: $path);
        $check = new Php2Shell($this->reproduce, true, new Php2ShellPoc(), $this->pocDir);

        try {
            $findings = $check->analyze($target, []);
            self::assertCount(1, $findings);
            self::assertStringContainsString('invalid', $findings[0]->evidence);
        } finally {
            @unlink($path);
        }
    }

    public function testTheCheckAsksForNoPaths(): void
    {
        $check = new Php2Shell($this->reproduce, true, new Php2ShellPoc(), $this->pocDir);

        self::assertSame([], $check->paths(new Target('https://app.example/'), null));
    }
}
