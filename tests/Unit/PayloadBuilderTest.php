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

    private function hashFile(string $path): string
    {
        return (string) hash_file('sha256', $path);
    }

    public function testRotateBodiesMatchTheOracle(): void
    {
        $builder = new PayloadBuilder();
        $a = $this->dir . '/rotate-a.bin';
        $b = $this->dir . '/rotate-b.bin';

        $builder->rotateA($a, 1);
        $builder->rotateB($b);

        self::assertSame(4_123_100, filesize($a));
        self::assertSame('8e549480d0cd07a14b357b422e0d05a207a32a01a082393350ab3f1d4923c6df', $this->hashFile($a));
        self::assertSame(192, filesize($b));
        self::assertSame('5b29950f7d421c5e7336441cf370d07e95a196b47c905bfbddef94e0d36c6937', $this->hashFile($b));
    }

    public function testStageOneBodiesMatchTheOracle(): void
    {
        $builder = new PayloadBuilder();
        $a = $this->dir . '/stage1-a.bin';
        $b = $this->dir . '/stage1-b.bin';
        $b63 = $this->dir . '/stage1-b63.bin';

        $builder->stage1A($a, 1);
        $builder->stage1B($b, 841, 79);
        $builder->stage1B($b63, 841, 63);

        self::assertSame(1_121_101, filesize($a));
        self::assertSame('0eec22a12ab40a92707f6c20b9a26735f2a51830a8b525c9a63244700bb3cca6', $this->hashFile($a));
        self::assertSame(93_685, filesize($b));
        self::assertSame('ecaf5a1898a7e0dd754c7633334a03f58059b262cfa870d366dc97af342f2397', $this->hashFile($b));
        self::assertSame(93_669, filesize($b63));
        self::assertSame('b234975725a875c6813bfac2219dad8fa447bace8a4445cbd254bc37309e8ac4', $this->hashFile($b63));
    }

    public function testStageTwoBodiesMatchTheOracle(): void
    {
        $builder = new PayloadBuilder();
        $a = $this->dir . '/stage2-a.bin';
        $b = $this->dir . '/stage2-b.bin';

        $builder->stage2A($a, 1);
        $builder->stage2B($b, 406, 16);

        self::assertSame(1_159_139, filesize($a));
        self::assertSame('acf5edb8783d9a47163119acef51a8409c1ebb15f0d2cc8659aeefc9fff168f2', $this->hashFile($a));
        self::assertSame(83_032, filesize($b));
        self::assertSame('31dcd8062596f239a5d8fb18050f8894865755573eae1814ccebb7729694988f', $this->hashFile($b));
    }

    public function testFakePayloadAndStageThreeMatchTheOracle(): void
    {
        $builder = new PayloadBuilder();
        $htAddress = 0x7ffffc4690d8;
        $zif = 0x7ffffe478370;
        $payload = $builder->fakePayload($htAddress, $zif, 'echo ABCDEFG>p');

        self::assertSame(167, strlen($payload['ht']));
        self::assertSame('6e4b5a7decc2b4116db07fc52807b66f2ba21795d8218b6f4bfc0e22efce1860', hash('sha256', $payload['ht']));
        self::assertSame(55, strlen((string) $payload['ref']));
        self::assertSame('c08e142e8724cc17b940e6504ab787d6d78c0bedc0d1a767eabd72a6c4a1638e', hash('sha256', (string) $payload['ref']));
        self::assertNotNull($payload['carrier']);
        self::assertSame(15, strlen($payload['carrier']));

        $a = $this->dir . '/stage3-a.bin';
        $b = $this->dir . '/stage3-b.bin';
        $builder->stage3A($a, array_fill(0, 6, [31, 31]), 1);
        $builder->stage3B($b, $payload['ht'], $payload['ref'], $payload['carrier']);

        self::assertSame(1_049_815, filesize($a));
        self::assertSame('12ee947dd1f3fbf68170b42a1b5d3484a46d75f8280bea9c01c34d11702d0154', $this->hashFile($a));
        self::assertSame(4_278, filesize($b));
        self::assertSame('57943ac097690841320b0d12664d00c0ebb755147e543cfe591a6183a6c5a06e', $this->hashFile($b));
    }

    public function testItRejectsACommandLongerThanTheCarrier(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        (new PayloadBuilder())->fakePayload(0x7ffffc4690d8, 0x7ffffe478370, 'echo too-long-marker>p');
    }
}
