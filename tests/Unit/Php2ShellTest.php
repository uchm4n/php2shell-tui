<?php

declare(strict_types=1);

namespace Php2ShellTui\Tests\Unit;

use Php2ShellTui\Check\Php2Shell;
use Php2ShellTui\Data\Reproduce;
use Php2ShellTui\Poc\GuessPlan;
use Php2ShellTui\Poc\Php2ShellPoc;
use Php2ShellTui\Poc\PocResult;
use Php2ShellTui\Poc\Profile;
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

    public function testGuessModeTriesProfilesInOrderAndStopsOnProof(): void
    {
        $calls = [];
        $runner = static function (Target $target, Profile $profile, ?int $workers, int $timeout) use (&$calls): PocResult {
            $calls[] = $profile->id();

            return new PocResult(true, 'RCE confirmed', 'MARKER', null, 'https://app.example/p');
        };

        $guess = new GuessPlan([
            'php-8.4.26-apache-bookworm-amd64',
            'php-8.5.11-apache-bookworm-aarch64',
        ]);
        $check = new Php2Shell($this->reproduce, true, new Php2ShellPoc(), $this->pocDir, $guess, null, $runner);

        $findings = $check->analyze(new Target('https://app.example/'), []);

        self::assertCount(1, $findings);
        self::assertSame('php2shell-rce', $findings[0]->id);
        self::assertSame(['php-8.4.26-apache-bookworm-amd64'], $calls);
    }

    public function testGuessModeStopsOnATerminalResult(): void
    {
        $calls = [];
        $runner = static function (Target $target, Profile $profile, ?int $workers, int $timeout) use (&$calls): PocResult {
            $calls[] = $profile->id();

            return new PocResult(false, 'worker pinning failed', terminal: true);
        };

        $guess = new GuessPlan([
            'php-8.4.26-apache-bookworm-amd64',
            'php-8.5.11-apache-bookworm-aarch64',
        ]);
        $check = new Php2Shell($this->reproduce, true, new Php2ShellPoc(), $this->pocDir, $guess, null, $runner);

        $findings = $check->analyze(new Target('https://app.example/'), []);

        self::assertCount(1, $findings);
        self::assertSame('php2shell-poc-inconclusive', $findings[0]->id);
        self::assertCount(1, $calls);
        self::assertStringContainsString('stopped', $findings[0]->evidence);
    }

    public function testGuessModeSkipsTheOtherArchitecture(): void
    {
        $called = false;
        $runner = static function (Target $target, Profile $profile, ?int $workers, int $timeout) use (&$called): PocResult {
            $called = true;

            return new PocResult(false, 'not reached');
        };

        $guess = new GuessPlan(['php-8.5.11-apache-bookworm-aarch64'], arch: 'amd64');
        $check = new Php2Shell($this->reproduce, true, new Php2ShellPoc(), $this->pocDir, $guess, null, $runner);

        $findings = $check->analyze(new Target('https://app.example/'), []);

        self::assertFalse($called);
        self::assertCount(1, $findings);
        self::assertStringContainsString('skipped', $findings[0]->evidence);
    }

    public function testGuessModeHonorsTheAttemptCap(): void
    {
        $calls = 0;
        $runner = static function (Target $target, Profile $profile, ?int $workers, int $timeout) use (&$calls): PocResult {
            $calls++;

            return new PocResult(false, 'no leak');
        };

        $guess = new GuessPlan([
            'php-8.4.26-apache-bookworm-amd64',
            'php-8.5.11-apache-bookworm-amd64',
        ], maxAttempts: 1);
        $check = new Php2Shell($this->reproduce, true, new Php2ShellPoc(), $this->pocDir, $guess, null, $runner);

        $findings = $check->analyze(new Target('https://app.example/'), []);

        self::assertSame(1, $calls);
        self::assertCount(1, $findings);
        self::assertSame('php2shell-poc-inconclusive', $findings[0]->id);
        self::assertStringContainsString('tried 1 profile(s)', $findings[0]->evidence);
    }

    public function testGuessModeReportsEveryAttemptWithoutClaimingSafety(): void
    {
        $runner = static fn (Target $target, Profile $profile, ?int $workers, int $timeout): PocResult => new PocResult(false, 'no leak');

        $guess = new GuessPlan([
            'php-8.4.26-apache-bookworm-amd64',
            'php-8.5.11-apache-bookworm-amd64',
        ], maxAttempts: 2);
        $check = new Php2Shell($this->reproduce, true, new Php2ShellPoc(), $this->pocDir, $guess, null, $runner);

        $findings = $check->analyze(new Target('https://app.example/'), []);

        self::assertCount(1, $findings);
        self::assertSame('php2shell-poc-inconclusive', $findings[0]->id);
        self::assertStringContainsString('php-8.4.26-apache-bookworm-amd64', $findings[0]->evidence);
        self::assertStringContainsString('php-8.5.11-apache-bookworm-amd64', $findings[0]->evidence);
        self::assertStringContainsString('do not treat this as safe', $findings[0]->exploit);
    }

    public function testGuessModeDoesNothingWithoutVerify(): void
    {
        $guess = new GuessPlan(['php-8.4.26-apache-bookworm-amd64']);
        $check = new Php2Shell($this->reproduce, false, new Php2ShellPoc(), $this->pocDir, $guess);

        self::assertSame([], $check->analyze(new Target('https://app.example/'), []));
    }

    public function testGuessModeSkipsAMissingProfile(): void
    {
        $guess = new GuessPlan(['no-such-profile']);
        $check = new Php2Shell($this->reproduce, true, new Php2ShellPoc(), $this->pocDir, $guess);

        $findings = $check->analyze(new Target('https://app.example/'), []);

        self::assertCount(1, $findings);
        self::assertStringContainsString('profile not found', $findings[0]->evidence);
    }

    public function testGuessModeReportsVerificationProgress(): void
    {
        $events = [];
        $progress = static function (string $label, string $phase, int $done, int $total) use (&$events): void {
            if ($phase === 'verify') {
                $events[] = [$done, $total];
            }
        };
        $runner = static fn (Target $target, Profile $profile, ?int $workers, int $timeout): PocResult => new PocResult(false, 'no leak');

        $guess = new GuessPlan([
            'php-8.4.26-apache-bookworm-amd64',
            'php-8.5.11-apache-bookworm-amd64',
        ], maxAttempts: 2);
        $check = new Php2Shell($this->reproduce, true, new Php2ShellPoc(), $this->pocDir, $guess, null, $runner);
        $check->setProgress($progress, null);

        $check->analyze(new Target('https://app.example/'), []);

        self::assertSame([[1, 2], [2, 2]], $events);
    }
}
