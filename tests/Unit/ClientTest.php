<?php

declare(strict_types=1);

namespace Php2ShellTui\Tests\Unit;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Response;
use Php2ShellTui\Http\Client;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

final class ClientTest extends TestCase
{
    private function client(callable $handler, int $delayMs = 0): Client
    {
        return new Client(new GuzzleClient([
            'handler' => HandlerStack::create($handler),
        ]), $delayMs);
    }

    public function testPostUrlEncodedSendsFormParamsAndHeaders(): void
    {
        $seen = null;
        $client = $this->client(function (RequestInterface $request) use (&$seen): PromiseInterface {
            $seen = $request;

            return Create::promiseFor(new Response(200, [], 'ok'));
        });

        $response = $client->post(
            'https://example.com/',
            ['X-Test' => 'yes'],
            ['test_field' => 'test_value'],
        );

        self::assertSame(200, $response?->getStatusCode());
        self::assertNotNull($seen);
        self::assertSame('POST', $seen->getMethod());
        self::assertSame('application/x-www-form-urlencoded', $seen->getHeaderLine('Content-Type'));
        self::assertSame('test_field=test_value', (string) $seen->getBody());
        self::assertSame('yes', $seen->getHeaderLine('X-Test'));
        self::assertSame('', $seen->getHeaderLine('Expect'));
    }

    public function testPostMultipartSendsMultipartFields(): void
    {
        $seen = null;
        $client = $this->client(function (RequestInterface $request) use (&$seen): PromiseInterface {
            $seen = $request;

            return Create::promiseFor(new Response(200, [], 'ok'));
        });

        $response = $client->post(
            'https://example.com/',
            [],
            ['test_field' => 'test_value'],
            true,
        );

        self::assertSame(200, $response?->getStatusCode());
        self::assertNotNull($seen);
        self::assertStringStartsWith('multipart/form-data; boundary=', $seen->getHeaderLine('Content-Type'));
        self::assertStringContainsString('name="test_field"', (string) $seen->getBody());
        self::assertStringContainsString('test_value', (string) $seen->getBody());
    }

    public function testPostDoesNotFollowRedirects(): void
    {
        $requests = [];
        $client = $this->client(function (RequestInterface $request) use (&$requests): PromiseInterface {
            $requests[] = $request;

            return Create::promiseFor(new Response(302, ['Location' => 'https://other.example/'], ''));
        });

        $response = $client->post('https://example.com/', [], ['a' => 'b']);

        self::assertSame(302, $response?->getStatusCode());
        self::assertCount(1, $requests);
        self::assertSame('example.com', $requests[0]->getUri()->getHost());
    }

    public function testPostDoesNotThrowOnHttpErrors(): void
    {
        $client = $this->client(
            static fn (): PromiseInterface => Create::promiseFor(new Response(500, [], 'error')),
        );

        $response = $client->post('https://example.com/', [], ['a' => 'b']);

        self::assertSame(500, $response?->getStatusCode());
    }

    public function testPostReturnsNullOnTransportError(): void
    {
        $client = $this->client(
            static fn (): PromiseInterface => Create::rejectionFor(new \RuntimeException('boom')),
        );

        self::assertNull($client->post('https://example.com/', [], ['a' => 'b']));
    }

    public function testPostAsyncReturnsAPromise(): void
    {
        $client = $this->client(
            static fn (): PromiseInterface => Create::promiseFor(new Response(200, [], 'ok')),
        );

        $promise = $client->postAsync('https://example.com/', [], ['a' => 'b']);

        self::assertInstanceOf(PromiseInterface::class, $promise);
        self::assertSame(200, $promise->wait()->getStatusCode());
    }

    public function testPostHonorsTheClientDelay(): void
    {
        $seenDelay = null;
        $client = $this->client(function (RequestInterface $request, array $options) use (&$seenDelay): PromiseInterface {
            $seenDelay = $options['delay'] ?? null;

            return Create::promiseFor(new Response(200, [], 'ok'));
        }, 25);

        $client->post('https://example.com/', [], ['a' => 'b']);

        self::assertSame(25, $seenDelay);
    }
}
