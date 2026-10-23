<?php

declare(strict_types=1);

namespace Php2ShellTui\Tests\Unit;

use Php2ShellTui\Poc\Profile;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PocProfileTest extends TestCase
{
    private const FIXTURE = __DIR__ . '/../Fixture/profile-8.4.26.json';

    /**
     * @return array<string, mixed>
     */
    private function valid(): array
    {
        return json_decode((string) file_get_contents(self::FIXTURE), true, 512, JSON_THROW_ON_ERROR);
    }

    public function testItLoadsAValidProfile(): void
    {
        $profile = Profile::fromFile(self::FIXTURE);

        self::assertSame('php-8.4.26-apache-bookworm-amd64', $profile->id());
        self::assertSame('8.4.26', $profile->phpVersion());
        self::assertSame('apache2handler', $profile->sapi());
        self::assertSame('amd64', $profile->arch());
        self::assertSame(150, $profile->workers());
        self::assertTrue($profile->rceVerified());
        self::assertSame('0x465370', $profile->offsets()['zif_system']);
        self::assertSame(78, $profile->stages()['a1_big']);
    }

    public function testItNormalizesX8664ToAmd64(): void
    {
        $data = $this->valid();
        $data['arch'] = 'x86_64';

        self::assertSame('amd64', Profile::fromArray($data)->arch());
    }

    public function testItNormalizesArm64ToAarch64(): void
    {
        $data = $this->valid();
        $data['arch'] = 'arm64';

        self::assertSame('aarch64', Profile::fromArray($data)->arch());
    }

    public function testItRejectsAMissingFile(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Profile::fromFile(__DIR__ . '/no-such-profile.json');
    }

    public function testItRejectsMalformedJson(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'p2s-profile-');
        self::assertNotFalse($path);
        file_put_contents($path, '{');

        try {
            $this->expectException(\InvalidArgumentException::class);
            Profile::fromFile($path);
        } finally {
            @unlink($path);
        }
    }

    public function testItRejectsANonObjectJson(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'p2s-profile-');
        self::assertNotFalse($path);
        file_put_contents($path, '[]');

        try {
            $this->expectException(\InvalidArgumentException::class);
            Profile::fromFile($path);
        } finally {
            @unlink($path);
        }
    }

    public static function missingFields(): array
    {
        return [['id'], ['php_version'], ['sapi'], ['arch'], ['workers']];
    }

    #[DataProvider('missingFields')]
    public function testItRejectsAMissingRequiredField(string $field): void
    {
        $data = $this->valid();
        unset($data[$field]);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($field);
        Profile::fromArray($data);
    }

    public static function invalidWorkers(): array
    {
        return [[0], [-1], ['150']];
    }

    #[DataProvider('invalidWorkers')]
    public function testItRejectsInvalidWorkers(mixed $workers): void
    {
        $data = $this->valid();
        $data['workers'] = $workers;

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('workers');
        Profile::fromArray($data);
    }

    public function testItRejectsUnknownArchitectures(): void
    {
        $data = $this->valid();
        $data['arch'] = 'sparc';

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('arch');
        Profile::fromArray($data);
    }

    public function testItRejectsNonBooleanVerificationFlags(): void
    {
        $data = $this->valid();
        $data['rce_verified'] = 1;

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('rce_verified');
        Profile::fromArray($data);
    }

    public function testItRejectsANonArrayOffsetsBlock(): void
    {
        $data = $this->valid();
        $data['offsets'] = 'nope';

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('offsets');
        Profile::fromArray($data);
    }

    public function testAVerifiedProfileRequiresItsBuildData(): void
    {
        $data = $this->valid();
        unset($data['offsets']);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('offsets');
        Profile::fromArray($data);
    }

    public function testAVerifiedProfileRequiresTheOffsetKeys(): void
    {
        $data = $this->valid();
        $data['offsets'] = ['zif_system' => '0x465370'];

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('zval_ptr_dtor');
        Profile::fromArray($data);
    }

    public function testAVerifiedProfileRequiresTheStageKeys(): void
    {
        $data = $this->valid();
        unset($data['stages']['b1_spec']);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('b1_spec');
        Profile::fromArray($data);
    }

    public function testEveryShippedProfileLoadsAndMatchesItsFileName(): void
    {
        $files = glob(__DIR__ . '/../../src/Data/poc/*.json') ?: [];

        self::assertNotEmpty($files);

        foreach ($files as $file) {
            $profile = Profile::fromFile($file);
            self::assertSame(pathinfo($file, PATHINFO_FILENAME), $profile->id(), $file);
        }
    }
}
