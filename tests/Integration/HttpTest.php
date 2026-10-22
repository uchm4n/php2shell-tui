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
        self::waitForServer();
    }

    public static function tearDownAfterClass(): void
    {
        if (is_resource(self::$process)) {
            proc_terminate(self::$process);
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

    private static function waitForServer(): void
    {
        $deadline = microtime(true) + 10.0;

        while (microtime(true) < $deadline) {
            $socket = @fsockopen('127.0.0.1', (int) self::$port, $errno, $errstr, 0.2);
            if (is_resource($socket)) {
                fclose($socket);

                return;
            }

            usleep(50_000);
        }

        self::fail('The fixture server did not start.');
    }
}
