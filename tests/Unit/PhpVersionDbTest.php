<?php

declare(strict_types=1);

namespace Php2Scan\Tests\Unit;

use Php2Scan\PhpVersionDb;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PhpVersionDbTest extends TestCase
{
    private PhpVersionDb $db;

    protected function setUp(): void
    {
        $this->db = new PhpVersionDb(__DIR__ . '/../../data/php-affected.json');
    }

    public static function affectedVersions(): array
    {
        return [
            ['5.6.40', true],
            ['7.4.33', true],
            ['8.0.30', true],
            ['8.1.29', true],
            ['8.2.34', true],
            ['8.2.35', false],
            ['8.3.35', true],
            ['8.3.36', false],
            ['8.4.26', true],
            ['8.4.27', false],
            ['8.5.11', true],
            ['8.5.12', false],
        ];
    }

    #[DataProvider('affectedVersions')]
    public function testItKnowsWhichVersionsAreAffected(string $version, bool $expected): void
    {
        self::assertSame($expected, $this->db->isAffected($version));
    }

    public function testItNormalisesVersionStrings(): void
    {
        self::assertSame('8.2.12', $this->db->normalize('PHP/8.2.12'));
        self::assertSame('8.2.12', $this->db->normalize('8.2.12RC1'));
        self::assertSame('8.2.12', $this->db->normalize('8.2.12-1ubuntu2.14'));
        self::assertSame('8.2.0', $this->db->normalize('8.2'));
        self::assertSame('8.0.0', $this->db->normalize('8'));
    }

    public function testItRejectsAnUnparseableVersion(): void
    {
        self::assertNull($this->db->normalize('not-a-version'));
        self::assertNull($this->db->branch('not-a-version'));
    }

    public function testItKnowsTheBranchAndItsFixedRelease(): void
    {
        self::assertSame('8.2', $this->db->branch('8.2.34'));
        self::assertSame('8.2.35', $this->db->fixedFor('8.2.34'));
        self::assertSame('8.5.12', $this->db->fixedFor('8.5.11'));
    }

    public function testBranchesBelowEightPointTwoHaveNoFix(): void
    {
        self::assertNull($this->db->firstFixed('8.1'));
        self::assertNull($this->db->firstFixed('7.4'));
        self::assertTrue($this->db->isAffected('8.1.29'));
    }

    public function testItKnowsTheNewestKnownRelease(): void
    {
        self::assertSame('8.5.12', $this->db->newestKnown());
    }

    public function testItKnowsTheCves(): void
    {
        self::assertSame(['CVE-2026-109618', 'CVE-2026-109619'], $this->db->cves());
        self::assertSame('PHP2Shell', $this->db->advisoryName());
    }

    public function testItCanBeLoadedThroughTheAlias(): void
    {
        $db = PhpVersionDb::fromFile(__DIR__ . '/../../data/php-affected.json');

        self::assertSame('8.5.12', $db->newestKnown());
    }

    public function testItFailsLoudlyOnAMissingDatabase(): void
    {
        $this->expectException(\RuntimeException::class);
        new PhpVersionDb(__DIR__ . '/../../data/no-such-file.json');
    }
}
