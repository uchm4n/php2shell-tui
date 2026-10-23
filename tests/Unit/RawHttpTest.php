<?php

declare(strict_types=1);

namespace Php2ShellTui\Tests\Unit;

use Php2ShellTui\Poc\RawHttp;
use PHPUnit\Framework\TestCase;

final class RawHttpTest extends TestCase
{
    /**
     * @return array{int, string, resource, string}
     */
    private function server(string $mode): array
    {
        $port = self::findFreePort();
        $dir = sys_get_temp_dir() . '/p2s-raw-' . bin2hex(random_bytes(6));
        mkdir($dir, 0o755, true);
        $capture = $dir . '/capture';
        $ready = $dir . '/ready';

        $process = proc_open(
            [PHP_BINARY, __DIR__ . '/../Fixture/raw_server.php', (string) $port, $capture, $ready, $mode],
            [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
            $pipes,
        );

        self::assertIsResource($process);
        $deadline = microtime(true) + 5.0;
        while (microtime(true) < $deadline) {
            if (is_file($ready)) {
                return [$port, $capture, $process, $dir];
            }
            usleep(10_000);
        }

        self::fail('raw server did not start');
    }

    /**
     * @param resource $process
     */
    private function stopServer($process, string $dir): void
    {
        proc_terminate($process, SIGKILL);
        proc_close($process);

        foreach (glob($dir . '/*') ?: [] as $path) {
            @unlink($path);
        }
        @rmdir($dir);
    }

    private static function findFreePort(): int
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        $name = stream_socket_get_name($socket, false);
        fclose($socket);

        return (int) substr((string) $name, strrpos((string) $name, ':') + 1);
    }

    public function testSendChunkedSendsChunkedFramingAndReturnsTheResponse(): void
    {
        [$port, $capture, $process, $dir] = $this->server('chunked');
        $body = $dir . '/body.bin';
        file_put_contents($body, 'hello world');

        try {
            $http = new RawHttp('http', '127.0.0.1', $port, 2.0, ['Host' => 'lab.example']);
            $response = $http->sendChunked('/index.php', $body);
            $http->close();

            self::assertStringContainsString('HTTP/1.1 200 OK', $response);
            self::assertStringContainsString('OK', $response);

            $request = (string) file_get_contents($capture);
            self::assertStringContainsString('POST /index.php HTTP/1.1', $request);
            self::assertStringContainsString('Host: lab.example', $request);
            self::assertStringContainsString('Content-Type: multipart/form-data; boundary=CCCCCCCCCC', $request);
            self::assertStringContainsString('Transfer-Encoding: chunked', $request);
            self::assertStringNotContainsString('Content-Length:', $request);
            self::assertStringContainsString("b\r\nhello world\r\n0\r\n\r\n", $request);
        } finally {
            $this->stopServer($process, $dir);
        }
    }

    public function testSendBodySendsContentLengthAndReturnsTheResponse(): void
    {
        [$port, $capture, $process, $dir] = $this->server('body');
        $body = $dir . '/body.bin';
        file_put_contents($body, 'hello');

        try {
            $http = new RawHttp('http', '127.0.0.1', $port, 2.0, ['Host' => 'lab.example']);
            $response = $http->sendBody('/index.php', $body, 'multipart/form-data; boundary=CCCCCCCCCC');
            $http->close();

            self::assertStringContainsString('HTTP/1.1 200 OK', $response);
            $request = (string) file_get_contents($capture);
            self::assertStringContainsString('Content-Length: 5', $request);
            self::assertStringContainsString('hello', $request);
            self::assertStringNotContainsString('Transfer-Encoding: chunked', $request);
        } finally {
            $this->stopServer($process, $dir);
        }
    }

    public function testSendBodyHandlesInterimResponses(): void
    {
        [$port, $capture, $process, $dir] = $this->server('interim');
        $body = $dir . '/body.bin';
        file_put_contents($body, 'hello');

        try {
            $http = new RawHttp('http', '127.0.0.1', $port, 2.0);
            $response = $http->sendBody('/index.php', $body, 'multipart/form-data; boundary=CCCCCCCCCC');
            $http->close();

            self::assertStringContainsString('100 Continue', $response);
            self::assertStringContainsString('200 OK', $response);
            self::assertStringContainsString('OK', $response);
        } finally {
            $this->stopServer($process, $dir);
        }
    }

    public function testOpenIncompletePostHoldsTheConnectionAndSendsContentLength(): void
    {
        [$port, $capture, $process, $dir] = $this->server('incomplete');

        try {
            $http = new RawHttp('http', '127.0.0.1', $port, 2.0);
            $socket = $http->openIncompletePost('/index.php', 1048576);

            $deadline = microtime(true) + 5.0;
            while (microtime(true) < $deadline && !is_file($capture)) {
                usleep(10_000);
            }

            $request = (string) file_get_contents($capture);
            self::assertStringContainsString('POST /index.php HTTP/1.1', $request);
            self::assertStringContainsString('Content-Type: application/x-www-form-urlencoded', $request);
            self::assertStringContainsString('Content-Length: 1048576', $request);
            self::assertStringContainsString('Connection: keep-alive', $request);
            self::assertStringEndsWith('x', $request);

            $http->close();
            self::assertFalse(is_resource($socket));
        } finally {
            $this->stopServer($process, $dir);
        }
    }

    public function testItRejectsAnUnsupportedScheme(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new RawHttp('ftp', '127.0.0.1', 80, 1.0);
    }

    public function testItRejectsAnInvalidPort(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new RawHttp('http', '127.0.0.1', 0, 1.0);
    }

    public function testItRejectsAnUnreadableBodyFile(): void
    {
        $http = new RawHttp('http', '127.0.0.1', 9, 1.0);

        $this->expectException(\RuntimeException::class);
        $http->sendChunked('/index.php', '/no/such/body.bin');
    }

    public function testCloseIsIdempotent(): void
    {
        $http = new RawHttp('http', '127.0.0.1', 9, 1.0);
        $http->close();
        $http->close();

        self::assertTrue(true);
    }
}
