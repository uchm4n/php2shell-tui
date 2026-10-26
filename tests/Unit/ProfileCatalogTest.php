<?php

declare(strict_types=1);

namespace Php2ShellTui\Tests\Unit;

use Php2ShellTui\Poc\ProfileCatalog;
use PHPUnit\Framework\TestCase;

final class ProfileCatalogTest extends TestCase
{
    private function catalog(): ProfileCatalog
    {
        return new ProfileCatalog(__DIR__ . '/../../src/Data/poc');
    }

    public function testItSelectsAnExactVersionAndArch(): void
    {
        $selection = $this->catalog()->select('8.4.26', 'amd64', null, 'debian');

        self::assertNotNull($selection['profile']);
        self::assertSame('php-8.4.26-bookworm-amd64', $selection['profile']->id());
    }

    public function testItRequiresAnArchWhenTwoBuildsShareAVersion(): void
    {
        $selection = $this->catalog()->select('8.5.11', null, null, 'debian');

        self::assertNull($selection['profile']);
        self::assertStringContainsString('arch', $selection['reason']);
    }

    public function testItSelectsTheArmBuildWhenAsked(): void
    {
        $selection = $this->catalog()->select('8.5.11', 'aarch64', null, 'debian');

        self::assertNotNull($selection['profile']);
        self::assertSame('php-8.5.11-bookworm-aarch64', $selection['profile']->id());
    }

    public function testItRejectsABranchInsteadOfAPatchRelease(): void
    {
        $selection = $this->catalog()->select('8.5', null, null, 'debian');

        self::assertNull($selection['profile']);
        self::assertStringContainsString('patch release', $selection['reason']);
    }

    public function testItRejectsAProfileForAnUncalibratedVersion(): void
    {
        $selection = $this->catalog()->select('7.4.33', null, null, 'debian');

        self::assertNull($selection['profile']);
        self::assertStringContainsString('no calibrated profile', $selection['reason']);
    }

    public function testItRejectsADistroMismatch(): void
    {
        $selection = $this->catalog()->select('8.4.26', 'amd64', null, 'ubuntu');

        self::assertNull($selection['profile']);
        self::assertStringContainsString('debian', $selection['reason']);
    }

    public function testItSelectsAnExplicitProfileWhenTheVersionIsHidden(): void
    {
        $selection = $this->catalog()->select(null, null, 'php-8.4.26-bookworm-amd64', null);

        self::assertNotNull($selection['profile']);
        self::assertSame('php-8.4.26-bookworm-amd64', $selection['profile']->id());
    }

    public function testItRejectsAnUnverifiedProfileEvenWhenExplicitlyPassed(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'p2s-unverified-');
        self::assertNotFalse($path);
        $data = json_decode((string) file_get_contents(
            __DIR__ . '/../../src/Data/poc/php-8.4.26-bookworm-amd64.json'
        ), true, 512, JSON_THROW_ON_ERROR);
        $data['rce'] = false;
        file_put_contents($path, json_encode($data, JSON_THROW_ON_ERROR));

        try {
            $selection = $this->catalog()->select(null, null, $path, null);
            self::assertNull($selection['profile']);
            self::assertStringContainsString('not verified', $selection['reason']);
        } finally {
            @unlink($path);
        }
    }

    public function testExactlyFiveVerifiedProfilesShip(): void
    {
        self::assertCount(5, $this->catalog()->all());
    }
}
