<?php

declare(strict_types=1);

namespace Php2Scan\Tests\Unit;

use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Promise\FulfilledPromise;
use GuzzleHttp\Psr7\Response;
use Php2Scan\Check\LocalFileInclusion;
use Php2Scan\Check\ReflectedXss;
use Php2Scan\Check\SqlInjection;
use Php2Scan\Data\Reproduce;
use Php2Scan\Http\Client;
use Php2Scan\Severity;
use Php2Scan\Target;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

final class InjectionChecksTest extends TestCase
{
    /**
     * @param list<Response> $responses
     */
    private function client(array $responses): Client
    {
        return new Client(new \GuzzleHttp\Client([
            'handler' => HandlerStack::create(new MockHandler($responses)),
            'http_errors' => false,
        ]), 0);
    }

    /**
     * A page that echoes the "q" parameter, optionally HTML-escaped.
     */
    private function reflectingClient(bool $encode): Client
    {
        $handler = static function (RequestInterface $request) use ($encode): FulfilledPromise {
            parse_str($request->getUri()->getQuery(), $query);
            $value = (string) ($query['q'] ?? '');

            return new FulfilledPromise(new Response(
                200,
                [],
                '<p>' . ($encode ? htmlspecialchars($value, ENT_QUOTES) : $value) . '</p>'
            ));
        };

        return new Client(new \GuzzleHttp\Client([
            'handler' => $handler,
            'http_errors' => false,
        ]), 0);
    }

    /**
     * @param list<string> $names
     * @return \Closure(Target): array<string, list<string>>
     */
    private function parameters(string $url = 'https://example.com/search?q=test', array $names = ['q']): \Closure
    {
        return static fn (Target $target): array => [$url => $names];
    }

    private function reproduce(): Reproduce
    {
        return new Reproduce(__DIR__ . '/../../data/repro');
    }

    public function testSqlInjectionIsConfirmedWhenThePayloadChangesTheResponse(): void
    {
        $client = $this->client([
            new Response(200, [], 'results for test'),
            new Response(200, [], 'results for test'),
            new Response(500, [], 'SQL syntax error'),
        ]);

        $findings = (new SqlInjection($this->reproduce(), $client, $this->parameters()))
            ->analyze(new Target('https://example.com'), []);

        self::assertCount(1, $findings);
        self::assertSame(Severity::High, $findings[0]->severity);
        self::assertNotEmpty($findings[0]->reproduce);
        self::assertStringContainsString('q=%27', $findings[0]->exploit);
    }

    public function testSqlInjectionIsNotReportedForIdenticalResponses(): void
    {
        $client = $this->client([
            new Response(200, [], 'results'),
            new Response(200, [], 'results'),
            new Response(200, [], 'results'),
            new Response(200, [], 'results'),
        ]);

        $findings = (new SqlInjection($this->reproduce(), $client, $this->parameters()))
            ->analyze(new Target('https://example.com'), []);

        self::assertSame([], $findings);
    }

    public function testAnUnstablePageIsNeverProbed(): void
    {
        // A CSRF token makes the page differ from itself, so a length change
        // caused by the payload would prove nothing.
        $client = $this->client([
            new Response(200, [], 'token=aaaa'),
            new Response(200, [], 'token=bbbbbbbb'),
        ]);

        $findings = (new SqlInjection($this->reproduce(), $client, $this->parameters()))
            ->analyze(new Target('https://example.com'), []);

        self::assertSame([], $findings);
    }

    public function testThePayloadIsAppliedToEveryDiscoveredParameterName(): void
    {
        $client = $this->client([
            new Response(200, [], 'item 7'),
            new Response(200, [], 'item 7'),
            new Response(500, [], 'error'),
        ]);

        $findings = (new SqlInjection(
            $this->reproduce(),
            $client,
            $this->parameters('https://example.com/item?id=7', ['id'])
        ))->analyze(new Target('https://example.com'), []);

        self::assertCount(1, $findings);
        self::assertStringContainsString('id=%27', $findings[0]->exploit);
    }

    public function testReflectedXssIsConfirmedWhenTheMarkerIsUnencoded(): void
    {
        $check = new ReflectedXss(
            $this->reproduce(),
            $this->reflectingClient(false),
            $this->parameters()
        );

        $findings = $check->analyze(new Target('https://example.com'), []);

        self::assertCount(1, $findings);
        self::assertSame(Severity::Medium, $findings[0]->severity);
        self::assertStringContainsString('reflected', $findings[0]->evidence);
    }

    public function testReflectedXssIsNotReportedWhenTheMarkerIsEncoded(): void
    {
        $check = new ReflectedXss(
            $this->reproduce(),
            $this->reflectingClient(true),
            $this->parameters()
        );

        self::assertSame([], $check->analyze(new Target('https://example.com'), []));
    }

    public function testItNeverSendsMoreThanSixtyProofOfConceptRequests(): void
    {
        $proofs = 0;
        $handler = static function (RequestInterface $request) use (&$proofs): FulfilledPromise {
            parse_str($request->getUri()->getQuery(), $query);

            foreach (array_keys($query) as $name) {
                if (str_starts_with((string) $name, 'p')) {
                    $proofs++;
                    break;
                }
            }

            return new FulfilledPromise(new Response(200, [], 'same'));
        };

        $client = new Client(new \GuzzleHttp\Client([
            'handler' => $handler,
            'http_errors' => false,
        ]), 0);

        $names = array_map(static fn (int $i): string => 'p' . $i, range(1, 40));

        $findings = (new SqlInjection(
            $this->reproduce(),
            $client,
            $this->parameters('https://example.com/item?id=7', $names)
        ))->analyze(new Target('https://example.com'), []);

        self::assertSame([], $findings);
        self::assertSame(60, $proofs);
    }

    public function testLocalFileInclusionIsConfirmedByThePasswdFile(): void
    {
        $client = $this->client([
            new Response(200, [], 'page'),
            new Response(200, [], 'page'),
            new Response(200, [], "root:x:0:0:root:/root:/bin/bash\n"),
        ]);

        $findings = (new LocalFileInclusion(
            $this->reproduce(),
            $client,
            $this->parameters('https://example.com/view?file=about', ['file'])
        ))->analyze(new Target('https://example.com'), []);

        self::assertCount(1, $findings);
        self::assertSame(Severity::High, $findings[0]->severity);
        self::assertStringContainsString('file=', $findings[0]->exploit);
    }

    public function testLocalFileInclusionIsNotReportedForANormalPage(): void
    {
        $client = $this->client([
            new Response(200, [], 'about us'),
            new Response(200, [], 'about us'),
            new Response(200, [], 'about us'),
        ]);

        $findings = (new LocalFileInclusion(
            $this->reproduce(),
            $client,
            $this->parameters('https://example.com/view?file=about', ['file'])
        ))->analyze(new Target('https://example.com'), []);

        self::assertSame([], $findings);
    }
}
