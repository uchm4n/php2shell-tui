<?php

declare(strict_types=1);

namespace Php2Scan\Tests\Unit;

use Php2Scan\Check\Tls;
use Php2Scan\Data\Reproduce;
use Php2Scan\Severity;
use Php2Scan\Target;
use PHPUnit\Framework\TestCase;

final class TlsTest extends TestCase
{
    public function testAPlainHttpTargetIsSkipped(): void
    {
        $check = new Tls(new Reproduce(__DIR__ . '/../../data/repro'));

        self::assertSame([], $check->analyze(new Target('http://example.com'), []));
    }

    public function testAnUnreachableTlsTargetProducesNoFindingRatherThanAnError(): void
    {
        $check = new Tls(new Reproduce(__DIR__ . '/../../data/repro'));
        $findings = $check->analyze(new Target('https://127.0.0.1:1/'), []);

        self::assertSame([], $findings);
    }

    public function testAnExpiredCertificateIsCritical(): void
    {
        $check = new Tls(
            new Reproduce(__DIR__ . '/../../data/repro'),
            static fn (string $host, int $port): array => [
                'validFrom' => time() - 86400 * 365,
                'validTo' => time() - 86400,
                'subject' => 'CN=' . $host,
            ],
        );

        $findings = $check->analyze(new Target('https://expired.example.com'), []);

        self::assertNotSame([], $findings);
        self::assertSame(Severity::Critical, $findings[0]->severity);
    }

    public function testACertificateExpiringSoonIsMedium(): void
    {
        $check = new Tls(
            new Reproduce(__DIR__ . '/../../data/repro'),
            static fn (string $host, int $port): array => [
                'validFrom' => time() - 86400,
                'validTo' => time() + 86400 * 5,
                'subject' => 'CN=' . $host,
            ],
        );

        $findings = $check->analyze(new Target('https://soon.example.com'), []);

        self::assertSame(Severity::Medium, $findings[0]->severity);
    }

    public function testAValidCertificateProducesNoFinding(): void
    {
        $check = new Tls(
            new Reproduce(__DIR__ . '/../../data/repro'),
            static fn (string $host, int $port): array => [
                'validFrom' => time() - 86400,
                'validTo' => time() + 86400 * 90,
                'subject' => 'CN=' . $host,
            ],
        );

        self::assertSame([], $check->analyze(new Target('https://ok.example.com'), []));
    }

    public function testACertificateIssuedForAnotherHostnameIsReported(): void
    {
        $check = new Tls(
            new Reproduce(__DIR__ . '/../../data/repro'),
            static fn (string $host, int $port): array => [
                'validFrom' => time() - 86400,
                'validTo' => time() + 86400 * 90,
                'subject' => 'CN=other.example.com',
            ],
        );

        $findings = $check->analyze(new Target('https://mismatch.example.com'), []);

        self::assertCount(1, $findings);
        self::assertSame('tls-hostname-mismatch', $findings[0]->id);
        self::assertSame(Severity::Medium, $findings[0]->severity);
        self::assertStringContainsString('mismatch.example.com', $findings[0]->evidence);
    }

    public function testASubjectAlternativeNameCoveringTheHostIsAccepted(): void
    {
        $check = new Tls(
            new Reproduce(__DIR__ . '/../../data/repro'),
            static fn (string $host, int $port): array => [
                'validFrom' => time() - 86400,
                'validTo' => time() + 86400 * 90,
                'subject' => 'CN=other.example.com',
                'san' => ['mismatch.example.com'],
            ],
        );

        self::assertSame([], $check->analyze(new Target('https://mismatch.example.com'), []));
    }

    public function testTheOpenSslOnelineSubjectIsUnderstood(): void
    {
        $check = new Tls(
            new Reproduce(__DIR__ . '/../../data/repro'),
            static fn (string $host, int $port): array => [
                'validFrom' => time() - 86400,
                'validTo' => time() + 86400 * 90,
                'subject' => '/C=US/O=Example Inc/CN=' . $host,
            ],
        );

        self::assertSame([], $check->analyze(new Target('https://ok.example.com'), []));
    }

    public function testAWildcardCertificateCoversOneLabelOnly(): void
    {
        $certificate = static fn (string $host, int $port): array => [
            'validFrom' => time() - 86400,
            'validTo' => time() + 86400 * 90,
            'subject' => 'CN=*.example.com',
        ];

        $check = new Tls(new Reproduce(__DIR__ . '/../../data/repro'), $certificate);
        self::assertSame([], $check->analyze(new Target('https://shop.example.com'), []));

        $check = new Tls(new Reproduce(__DIR__ . '/../../data/repro'), $certificate);
        $findings = $check->analyze(new Target('https://example.com'), []);
        self::assertCount(1, $findings);
        self::assertSame('tls-hostname-mismatch', $findings[0]->id);
    }

    public function testEveryFindingCarriesAReproduceStep(): void
    {
        $check = new Tls(
            new Reproduce(__DIR__ . '/../../data/repro'),
            static fn (string $host, int $port): array => [
                'validFrom' => time() - 86400 * 365,
                'validTo' => time() - 86400,
                'subject' => 'CN=other.example.com',
            ],
        );

        $findings = $check->analyze(new Target('https://expired.example.com'), []);

        self::assertNotSame([], $findings);

        foreach ($findings as $finding) {
            self::assertNotEmpty($finding->reproduce, $finding->id . ' must have reproduce steps');
            self::assertNotSame('', trim($finding->exploit));
        }
    }
}
