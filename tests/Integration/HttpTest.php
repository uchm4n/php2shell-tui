<?php

declare(strict_types=1);

namespace Php2Scan\Tests\Integration;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\CurlMultiHandler;
use GuzzleHttp\HandlerStack;
use PHPUnit\Framework\TestCase;
use Php2Scan\Http\Client;
use Php2Scan\Http\Pool;

final class HttpTest extends TestCase
{
    private static ?int $port = null;
    private static mixed $process = null;
    private static int $masterPid = 0;

    public static function setUpBeforeClass(): void
    {
        self::$port = self::findFreePort();
        self::$process = proc_open(
            sprintf('exec php -S 127.0.0.1:%d %s', self::$port, escapeshellarg(__DIR__ . '/../Fixture/server.php')),
            [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
            $pipes,
            null,
            // The built-in server is single threaded unless it forks workers.
            array_merge(getenv(), ['PHP_CLI_SERVER_WORKERS' => '8'])
        );
        // The pid has to be read here: once the process is reaped proc_get_status()
        // returns 0, and posix_kill(0, ...) would signal the whole process group.
        $status = proc_get_status(self::$process);
        self::$masterPid = (int) $status['pid'];
        self::waitForServer((int) self::$port);
    }

    public static function tearDownAfterClass(): void
    {
        // `php -S` ignores SIGTERM: neither the master nor its PHP_CLI_SERVER_WORKERS children
        // exit, so proc_close() would block forever and the port would stay bound for the next
        // run. Kill whatever holds the socket first, then the master.
        self::killListenersOnPort((int) self::$port);

        if (self::$masterPid > 1) {
            @posix_kill(self::$masterPid, SIGKILL);
        }

        if (is_resource(self::$process)) {
            proc_terminate(self::$process, SIGKILL);
            proc_close(self::$process);
        }
    }

    public function testThePoolFetchesEveryRequestAndReportsFailures(): void
    {
        [$pool] = self::pool(['max_total_connections' => 8, 'max_host_connections' => 2]);

        $base = sprintf('http://127.0.0.1:%d', self::$port);
        $results = $pool->run([
            ['url' => $base . '/', 'headers' => []],
            ['url' => $base . '/missing', 'headers' => []],
            ['url' => 'http://127.0.0.1:1/unreachable', 'headers' => []],
        ]);

        self::assertCount(3, $results);
        self::assertSame($base . '/', $results[0]['url']);
        self::assertSame(200, $results[0]['response']?->getStatusCode());
        self::assertNull($results[0]['error']);
        self::assertSame($base . '/missing', $results[1]['url']);
        self::assertSame(404, $results[1]['response']?->getStatusCode());
        self::assertNull($results[1]['error']);
        self::assertNull($results[2]['response']);
        self::assertNotNull($results[2]['error']);
    }

    public function testThePoolRunsRequestsConcurrently(): void
    {
        [$pool] = self::pool(['max_total_connections' => 8, 'max_host_connections' => 8]);

        $base = sprintf('http://127.0.0.1:%d', self::$port);
        $started = microtime(true);
        $pool->run([
            ['url' => $base . '/slow', 'headers' => []],
            ['url' => $base . '/slow', 'headers' => []],
            ['url' => $base . '/slow', 'headers' => []],
        ]);
        $elapsed = microtime(true) - $started;

        self::assertLessThan(2.5, $elapsed, 'Three one-second requests should overlap, not queue.');
    }

    public function testTheTickCallbackCanCancelAWait(): void
    {
        [$pool] = self::pool();

        $base = sprintf('http://127.0.0.1:%d', self::$port);
        $ticks = 0;
        $started = microtime(true);

        try {
            $pool->run(
                [['url' => $base . '/slow', 'headers' => []]],
                null,
                function () use (&$ticks): void {
                    $ticks++;
                    throw new \RuntimeException('cancelled');
                }
            );
            self::fail('The tick callback should abort the wait.');
        } catch (\RuntimeException $e) {
            self::assertSame('cancelled', $e->getMessage());
        }

        self::assertSame(1, $ticks);
        self::assertLessThan(0.9, microtime(true) - $started, 'The wait must abort before the slow response arrives.');
    }

    public function testThePoolReportsEverySettledRequest(): void
    {
        [$pool] = self::pool();

        $base = sprintf('http://127.0.0.1:%d', self::$port);
        $settled = [];
        $pool->run(
            [
                ['url' => $base . '/', 'headers' => []],
                ['url' => 'http://127.0.0.1:1/unreachable', 'headers' => []],
            ],
            function (string $url, ?\Psr\Http\Message\ResponseInterface $response, ?string $error) use (&$settled): void {
                // The callback fires in completion order, not in request order.
                $settled[$url] = [$response?->getStatusCode(), $error];
            }
        );

        self::assertCount(2, $settled);
        self::assertSame(200, $settled[$base . '/'][0]);
        self::assertNull($settled[$base . '/'][1]);
        self::assertNull($settled['http://127.0.0.1:1/unreachable'][0]);
        self::assertNotNull($settled['http://127.0.0.1:1/unreachable'][1]);
    }

    public function testThePoolReportsAnUnusableUrl(): void
    {
        [$pool] = self::pool();

        $base = sprintf('http://127.0.0.1:%d', self::$port);
        $results = $pool->run([
            ['url' => 'not-a-url', 'headers' => []],
            ['url' => $base . '/', 'headers' => []],
        ]);

        self::assertCount(2, $results);
        self::assertNull($results[0]['response']);
        self::assertNotNull($results[0]['error']);
        self::assertSame(200, $results[1]['response']?->getStatusCode());
    }

    public function testARedirectToAnotherHostIsNotFollowed(): void
    {
        [$pool] = self::pool();

        // The fixture redirects to "localhost", a different host than the
        // "127.0.0.1" the request was made to.
        $results = $pool->run([
            ['url' => sprintf('http://127.0.0.1:%d/redirect', self::$port), 'headers' => []],
        ]);

        // The 3xx itself is returned rather than the other host's body.
        self::assertNotNull($results[0]['response']);
        self::assertGreaterThanOrEqual(300, $results[0]['response']->getStatusCode());
        self::assertLessThan(400, $results[0]['response']->getStatusCode());
        self::assertStringNotContainsString('secure', (string) $results[0]['response']->getBody());
    }

    public function testARedirectToTheSameHostIsFollowed(): void
    {
        [$pool] = self::pool();

        $results = $pool->run([
            ['url' => sprintf('http://localhost:%d/redirect', self::$port), 'headers' => []],
        ]);

        self::assertSame(200, $results[0]['response']?->getStatusCode());
        self::assertSame('secure', (string) $results[0]['response']?->getBody());
    }

    public function testGetReturnsNullOnTransportFailure(): void
    {
        [, $client] = self::pool();

        self::assertNull($client->get('http://127.0.0.1:1/unreachable'));
    }

    public function testGetReturnsTheResponse(): void
    {
        [, $client] = self::pool();

        $response = $client->get(sprintf('http://127.0.0.1:%d/', self::$port));

        self::assertNotNull($response);
        self::assertSame(200, $response->getStatusCode());
    }

    public function testTheTeardownHelperReleasesThePort(): void
    {
        if (!function_exists('exec') || !function_exists('posix_kill') || !self::hasLsof()) {
            self::markTestSkipped('exec(), posix_kill() and lsof are needed to tear the fixture server down.');
        }

        $port = self::findFreePort();
        $process = proc_open(
            sprintf('exec php -S 127.0.0.1:%d %s', $port, escapeshellarg(__DIR__ . '/../Fixture/server.php')),
            [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
            $pipes,
            null,
            array_merge(getenv(), ['PHP_CLI_SERVER_WORKERS' => '1'])
        );

        try {
            self::waitForServer($port);
            self::assertNotSame([], self::listenersOnPort($port), 'the fixture server must hold the port');

            self::killListenersOnPort($port);

            // The kill is asynchronous, so give the kernel a moment to tear the socket down.
            $deadline = microtime(true) + 5.0;
            while (microtime(true) < $deadline && self::listenersOnPort($port) !== []) {
                usleep(50_000);
            }

            self::assertSame([], self::listenersOnPort($port), 'killListenersOnPort() must release the port');

            $socket = @stream_socket_server(sprintf('tcp://127.0.0.1:%d', $port), $errno, $errstr);
            self::assertNotFalse($socket, 'the port must be bindable again');
            fclose($socket);
        } finally {
            self::killListenersOnPort($port);

            if (is_resource($process)) {
                proc_terminate($process, SIGKILL);
                proc_close($process);
            }
        }
    }

    /**
     * @param array<string, int> $handlerOptions
     * @return array{Pool, Client}
     */
    private static function pool(array $handlerOptions = []): array
    {
        $handler = new CurlMultiHandler($handlerOptions);
        $client = new Client(new GuzzleClient([
            'handler' => HandlerStack::create($handler),
            'http_errors' => false,
            'timeout' => 10,
        ]), 0);
        $pool = new Pool($handler, $client);

        return [$pool, $client];
    }

    private static function findFreePort(): int
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        $name = stream_socket_get_name($socket, false);
        fclose($socket);

        return (int) substr((string) $name, strrpos((string) $name, ':') + 1);
    }

    private static function waitForServer(int $port): void
    {
        $deadline = microtime(true) + 10.0;

        while (microtime(true) < $deadline) {
            $socket = @fsockopen('127.0.0.1', $port, $errno, $errstr, 0.2);
            if (is_resource($socket)) {
                fclose($socket);

                return;
            }

            usleep(50_000);
        }

        self::fail('The fixture server did not start.');
    }

    private static function killListenersOnPort(int $port): void
    {
        if (!function_exists('exec') || !function_exists('posix_kill')) {
            return;
        }

        $pids = [];
        exec(sprintf('lsof -ti tcp:%d 2>/dev/null', $port), $pids);

        foreach ($pids as $pid) {
            $pid = (int) trim($pid);
            if ($pid > 1) {
                @posix_kill($pid, SIGKILL);
            }
        }
    }

    /**
     * @return list<int>
     */
    private static function listenersOnPort(int $port): array
    {
        if (!function_exists('exec')) {
            return [];
        }

        $pids = [];
        exec(sprintf('lsof -ti tcp:%d 2>/dev/null', $port), $pids);

        return array_values(array_map(static fn (string $pid): int => (int) trim($pid), $pids));
    }

    private static function hasLsof(): bool
    {
        if (!function_exists('exec')) {
            return false;
        }

        $output = [];
        $status = 1;
        exec('command -v lsof 2>/dev/null', $output, $status);

        return $status === 0;
    }
}
