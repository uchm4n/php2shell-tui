<?php

declare(strict_types=1);

namespace Php2ShellTui\Tests\Unit;

use Php2ShellTui\Poc\PocResult;
use PHPUnit\Framework\TestCase;

final class PocResultTest extends TestCase
{
    public function testAConfirmedResultCarriesTheProof(): void
    {
        $result = new PocResult(true, 'RCE confirmed', 'uid=33(www-data)', 'profile=test');

        self::assertTrue($result->confirmed);
        self::assertSame('RCE confirmed', $result->reason);
        self::assertSame('uid=33(www-data)', $result->proof);
        self::assertSame('profile=test', $result->evidence);
        self::assertNull($result->proofPath);
    }

    public function testAConfirmedResultCanCarryTheActualProofPath(): void
    {
        $result = new PocResult(true, 'RCE confirmed', 'marker', 'evidence', 'https://target.example/out/random');

        self::assertSame('https://target.example/out/random', $result->proofPath);
    }

    public function testAnUnconfirmedResultMayHaveNoProof(): void
    {
        $result = new PocResult(false, 'proof not obtained');

        self::assertFalse($result->confirmed);
        self::assertNull($result->proof);
        self::assertNull($result->evidence);
    }

    public function testAConfirmedResultRequiresProof(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new PocResult(true, 'RCE confirmed');
    }

    public function testTheReasonMustNotBeEmpty(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new PocResult(false, ' ');
    }
}
