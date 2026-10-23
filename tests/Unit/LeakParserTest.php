<?php

declare(strict_types=1);

namespace Php2ShellTui\Tests\Unit;

use Php2ShellTui\Poc\LeakParser;
use PHPUnit\Framework\TestCase;

final class LeakParserTest extends TestCase
{
    private static function response(string $cookie): string
    {
        return "HTTP/1.1 200 OK\r\nSet-Cookie: PHPSESSID=" . $cookie . "\r\n\r\n";
    }

    private static function encodedPointers(): string
    {
        $binary = '';
        $zdtor = 0x7ffffe671b60;
        $id = 0x7ffff3c00000;
        $main = 0x7ffffc400000;
        $other = 0x7ffff3a00000;

        for ($i = 0; $i < 1095; $i++) {
            $binary .= pack('P', $zdtor);
        }
        for ($i = 0; $i < 7495; $i++) {
            $binary .= pack('P', $id + $i * 8);
        }
        for ($i = 0; $i < 87; $i++) {
            $binary .= pack('P', $main + $i * 8);
        }
        for ($i = 0; $i < 79; $i++) {
            $binary .= pack('P', $other + $i * 8);
        }

        return rawurlencode($binary);
    }

    public function testItParsesAHeapLeak(): void
    {
        $leak = LeakParser::parse(self::response(self::encodedPointers()));

        self::assertSame(70_048, $leak['decoded']);
        self::assertSame(0x7ffffe671b60, $leak['zval_ptr_dtor']);
        self::assertSame(0x7ffffe013000, $leak['libphp']);
        self::assertSame(0x7ffffc400000, $leak['main_candidates'][0]);
        self::assertSame(7495, $leak['buckets'][0x7ffff3c00000]);
    }

    public function testItRejectsAResponseWithoutTheCookie(): void
    {
        $this->expectException(\RuntimeException::class);
        LeakParser::parse("HTTP/1.1 200 OK\r\n\r\n");
    }

    public function testItRejectsACookieWithoutPointers(): void
    {
        $this->expectException(\RuntimeException::class);
        LeakParser::parse(self::response(rawurlencode('not a pointer')));
    }
}
