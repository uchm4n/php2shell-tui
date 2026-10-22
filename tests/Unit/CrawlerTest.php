<?php

declare(strict_types=1);

namespace Php2Scan\Tests\Unit;

use GuzzleHttp\Psr7\Response;
use Php2Scan\Crawler\Crawler;
use Php2Scan\Http\Client;
use Php2Scan\Target;
use PHPUnit\Framework\TestCase;

final class CrawlerTest extends TestCase
{
    private function client(): Client
    {
        // Every URL these tests reach is supplied through $pages, so this client
        // never opens a socket.
        return new Client(new \GuzzleHttp\Client(['http_errors' => false]), 0);
    }

    public function testItCollectsQueryParametersFromThePageAndItsLinks(): void
    {
        $pages = [
            'https://example.com/' => new Response(200, [], '<a href="/search?q=test">search</a><form action="/detail"><input name="id"></form>'),
            'https://example.com/search?q=test' => new Response(200, [], '<p>results</p>'),
        ];

        $parameters = (new Crawler($this->client()))->parameters(new Target('https://example.com'), $pages);

        self::assertSame(['q'], $parameters['https://example.com/search?q=test']);
        self::assertSame(['id'], $parameters['https://example.com/detail']);
    }

    public function testATargetWithAPathIsCrawledAsGiven(): void
    {
        $pages = [
            'https://example.com/search?q=test' => new Response(200, [], '<p>results</p>'),
        ];

        $parameters = (new Crawler($this->client()))->parameters(
            new Target('https://example.com/search?q=test'),
            $pages
        );

        self::assertSame(['q'], $parameters['https://example.com/search?q=test']);
    }

    public function testATargetWithAQueryButNoPathIsCrawledAsGiven(): void
    {
        $pages = [
            'https://example.com?x=1' => new Response(200, [], '<p>ok</p>'),
        ];

        $parameters = (new Crawler($this->client()))->parameters(
            new Target('https://example.com?x=1'),
            $pages
        );

        self::assertSame(['x'], $parameters['https://example.com?x=1'] ?? []);
    }

    public function testItKeepsThePortWhenResolvingRelativeLinks(): void
    {
        $pages = [
            'http://127.0.0.1:8899/' => new Response(200, [], '<a href="/item?id=7">item</a>'),
            'http://127.0.0.1:8899/item?id=7' => new Response(200, [], '<p>item</p>'),
        ];

        $parameters = (new Crawler($this->client()))->parameters(new Target('http://127.0.0.1:8899'), $pages);

        self::assertSame(['id'], $parameters['http://127.0.0.1:8899/item?id=7']);
    }

    public function testItNeverLeavesTheAllowlistedHost(): void
    {
        $pages = [
            'https://example.com/' => new Response(200, [], '<a href="https://evil.example/steal?token=1">x</a>'),
        ];

        $parameters = (new Crawler($this->client()))->parameters(new Target('https://example.com'), $pages);

        self::assertSame([], $parameters);
    }

    public function testItOnlyFollowsLinksOneHopFromTheTargetByDefault(): void
    {
        $pages = [
            'https://example.com/' => new Response(200, [], '<a href="/a">a</a>'),
            'https://example.com/a' => new Response(200, [], '<a href="/b?deep=1">b</a>'),
        ];

        $parameters = (new Crawler($this->client()))->parameters(new Target('https://example.com'), $pages);

        self::assertArrayNotHasKey('https://example.com/b?deep=1', $parameters);
    }
}
