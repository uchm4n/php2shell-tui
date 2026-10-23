<?php

declare(strict_types=1);

namespace Php2ShellTui\Tests\Unit;

use GuzzleHttp\Psr7\Response;
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
            static fn (string $host, int $port): ?string => in_array($port, [3306, 443], true)
                ? 'TCP connection accepted'
                : null,
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
            static fn (string $host, int $port): ?string => null,
        );

        self::assertSame([], $check->analyze(new Target('https://example.com'), []));
    }

    public function testAnUnexpectedPortIsMedium(): void
    {
        $check = new OpenPorts(
            new Wordlists(__DIR__ . '/../../src/Data'),
            new Reproduce(__DIR__ . '/../../src/Data/repro'),
            static fn (string $host, int $port): ?string => $port === 8080 ? 'HTTP 200 (Server: nginx)' : null,
        );

        $findings = $check->analyze(new Target('https://example.com'), []);

        self::assertCount(1, $findings);
        self::assertSame(Severity::Medium, $findings[0]->severity);
        self::assertStringContainsString('8080', $findings[0]->evidence);
        self::assertStringContainsString('HTTP 200', $findings[0]->evidence);
    }

    public function testEveryFindingCarriesAReproduceStep(): void
    {
        $check = new OpenPorts(
            new Wordlists(__DIR__ . '/../../src/Data'),
            new Reproduce(__DIR__ . '/../../src/Data/repro'),
            static fn (string $host, int $port): ?string => $port === 5432 ? 'TCP connection accepted' : null,
        );

        $findings = $check->analyze(new Target('https://example.com'), []);

        self::assertNotSame([], $findings);

        foreach ($findings as $finding) {
            self::assertNotEmpty($finding->reproduce, $finding->id . ' must have reproduce steps');
            self::assertNotSame('', trim($finding->exploit));
        }
    }

    public function testACloudflareRedirectIsClassifiedAsCdnEdge(): void
    {
        $response = new Response(301, [
            'Server' => 'cloudflare',
            'Location' => 'https://lamart.ge/',
        ]);

        self::assertNull(OpenPorts::evidenceFromResponse($response));
    }

    public function testACloudflarePlainHttpErrorIsClassifiedAsCdnEdge(): void
    {
        $response = new Response(400, [
            'Server' => 'cloudflare',
            'Content-Length' => '253',
        ]);

        self::assertNull(OpenPorts::evidenceFromResponse($response));
    }

    public function testACloudflareRayHeaderIsAlsoCdnEdge(): void
    {
        $response = new Response(301, [
            'CF-RAY' => '8f2c1d3e4f5a6b7c-AMS',
            'Location' => 'https://lamart.ge/',
        ]);

        self::assertNull(OpenPorts::evidenceFromResponse($response));
    }

    public function testAnOrdinaryHttpServiceIsStillReported(): void
    {
        $response = new Response(200, ['Server' => 'nginx']);

        self::assertSame('HTTP 200 (Server: nginx)', OpenPorts::evidenceFromResponse($response));
    }
}
