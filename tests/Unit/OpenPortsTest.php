<?php

declare(strict_types=1);

namespace Php2ShellTui\Tests\Unit;

use Php2ShellTui\Check\OpenPorts;
use Php2ShellTui\Data\Reproduce;
use Php2ShellTui\Data\Wordlists;
use Php2ShellTui\Severity;
use Php2ShellTui\Target;
use PHPUnit\Framework\TestCase;

final class OpenPortsTest extends TestCase
{
    public function testAnExposedDatabasePortIsHighAndWebPortsAreNotReported(): void
    {
        $check = new OpenPorts(
            new Wordlists(__DIR__ . '/../../src/Data'),
            new Reproduce(__DIR__ . '/../../src/Data/repro'),
            static fn (string $host, int $port): bool => in_array($port, [3306, 443], true),
        );

        $findings = $check->analyze(new Target('https://example.com'), []);

        self::assertCount(1, $findings);
        self::assertSame(Severity::High, $findings[0]->severity);
        self::assertStringContainsString('3306', $findings[0]->evidence);
    }

    public function testEveryPortClosedProducesNoFinding(): void
    {
        $check = new OpenPorts(
            new Wordlists(__DIR__ . '/../../src/Data'),
            new Reproduce(__DIR__ . '/../../src/Data/repro'),
            static fn (string $host, int $port): bool => false,
        );

        self::assertSame([], $check->analyze(new Target('https://example.com'), []));
    }

    public function testAnUnexpectedPortIsMedium(): void
    {
        $check = new OpenPorts(
            new Wordlists(__DIR__ . '/../../src/Data'),
            new Reproduce(__DIR__ . '/../../src/Data/repro'),
            static fn (string $host, int $port): bool => $port === 8080,
        );

        $findings = $check->analyze(new Target('https://example.com'), []);

        self::assertCount(1, $findings);
        self::assertSame(Severity::Medium, $findings[0]->severity);
        self::assertStringContainsString('8080', $findings[0]->evidence);
    }

    public function testEveryFindingCarriesAReproduceStep(): void
    {
        $check = new OpenPorts(
            new Wordlists(__DIR__ . '/../../src/Data'),
            new Reproduce(__DIR__ . '/../../src/Data/repro'),
            static fn (string $host, int $port): bool => $port === 5432,
        );

        $findings = $check->analyze(new Target('https://example.com'), []);

        self::assertNotSame([], $findings);

        foreach ($findings as $finding) {
            self::assertNotEmpty($finding->reproduce, $finding->id . ' must have reproduce steps');
            self::assertNotSame('', trim($finding->exploit));
        }
    }
}
