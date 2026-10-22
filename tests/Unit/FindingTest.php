<?php

declare(strict_types=1);

namespace Php2ShellTui\Tests\Unit;

use Php2ShellTui\Finding;
use Php2ShellTui\Severity;
use PHPUnit\Framework\TestCase;

final class FindingTest extends TestCase
{
    public function testItCarriesEveryPartOfAReportableFinding(): void
    {
        $finding = new Finding(
            id: 'sensitive-file-env',
            title: 'Exposed .env',
            severity: Severity::High,
            target: 'legacy.example.com',
            evidence: 'HTTP 200, 1.2 KB, contains APP_KEY',
            exploit: 'curl https://legacy.example.com/.env and read the leaked credentials.',
            reproduce: ['curl -sS https://legacy.example.com/.env | head -20'],
        );

        self::assertSame('sensitive-file-env', $finding->id);
        self::assertSame(Severity::High, $finding->severity);
        self::assertSame(['curl -sS https://legacy.example.com/.env | head -20'], $finding->reproduce);
    }

    public function testItCarriesTheExploitSentenceVerbatim(): void
    {
        $finding = new Finding('x', 't', Severity::Low, 'host', 'e', 'Read the version with "php -v".', ['step']);

        self::assertSame('Read the version with "php -v".', $finding->exploit);
        self::assertNotSame('', trim($finding->exploit));
    }

    public function testItRejectsAnEmptyExploitSentence(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new Finding('x', 't', Severity::Low, 'host', 'e', '', ['step']);
    }

    public function testItRejectsAWhitespaceOnlyExploitSentence(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new Finding('x', 't', Severity::Low, 'host', 'e', "  \n\t ", ['step']);
    }

    public function testItIsImmutable(): void
    {
        $finding = new Finding('x', 't', Severity::Low, 'host', 'e', 'sentence', ['step']);

        $this->expectException(\Error::class);
        $finding->title = 'changed';
    }
}
