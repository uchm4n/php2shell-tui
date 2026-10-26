<?php

declare(strict_types=1);

namespace Php2ShellTui\Tests\Unit;

use Php2ShellTui\Poc\Profile;
use PHPUnit\Framework\TestCase;

final class ProfileTest extends TestCase
{
    private const PROFILE = __DIR__ . '/../../src/Data/poc/php-8.4.26-bookworm-amd64.json';

    /**
     * @return array<string, mixed>
     */
    private function data(): array
    {
        return json_decode(
            (string) file_get_contents(self::PROFILE),
            true,
            512,
            JSON_THROW_ON_ERROR,
        );
    }

    public function testTheVerifiedEightFourTwoSixProfileLoads(): void
    {
        $profile = Profile::fromFile(self::PROFILE);

        self::assertSame('php-8.4.26-bookworm-amd64', $profile->id());
        self::assertSame('8.4.26', $profile->phpVersion());
        self::assertSame('8.4', $profile->branch());
        self::assertSame('8.4.27', $profile->fixedIn());
        self::assertSame('amd64', $profile->arch());
        self::assertSame('apache2handler', $profile->sapi());
        self::assertSame('debian', $profile->distro());
        self::assertTrue($profile->rceVerified());
        self::assertSame(0x465370, $profile->libphp()['zif_system']);
        self::assertSame(0x65eb60, $profile->libphp()['zval_ptr_dtor']);
        self::assertSame(0x690d8, $profile->libphp()['htdata']);
        self::assertSame(841, $profile->stage1N());
        self::assertSame(79, $profile->stage1ForgeLen());
        self::assertSame(406, $profile->stage2T());
        self::assertSame(16, $profile->stage2V());
        self::assertCount(6, $profile->stage3Pads());
        self::assertSame([31, 31], $profile->stage3Pads()[0]);
        self::assertTrue($profile->stage3Carrier());
        self::assertSame(12, $profile->oomMb());
        self::assertSame(12, $profile->oomMarginMb());
        self::assertSame([8, 128], $profile->memoryLimitTestedMb());
        self::assertSame('bookworm', $profile->upstreamProfile());
    }

    public function testAnUnverifiedProfileIsNotSelectableRce(): void
    {
        $data = $this->data();
        $data['verified'] = true;
        $data['rce'] = false;

        self::assertFalse(Profile::fromArray($data)->rceVerified());
    }

    public function testExactlyFiveProfilesShip(): void
    {
        self::assertCount(5, glob(__DIR__ . '/../../src/Data/poc/*.json') ?: []);
    }
}
