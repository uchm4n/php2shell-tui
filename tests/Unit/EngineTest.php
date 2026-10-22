<?php

declare(strict_types=1);

namespace Php2Scan\Tests\Unit;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\CurlMultiHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Php2Scan\Check\Check;
use Php2Scan\Check\Registry;
use Php2Scan\Config;
use Php2Scan\Engine;
use Php2Scan\Finding;
use Php2Scan\Http\Client;
use Php2Scan\Http\Pool;
use Php2Scan\Severity;
use Php2Scan\Target;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

final class EngineTest extends TestCase
{
    public function testItRunsChecksAgainstEveryTargetAndCollectsFindings(): void
    {
        $urls = [];
        $engine = self::engine([self::check()], static fn (): ResponseInterface => new Response(200, [], 'ok'), $urls);

        $result = $engine->run(Config::fromArray([
            'targets' => ['https://one.example/', 'https://two.example/'],
            'checks' => ['php_presence' => true],
        ]));

        self::assertCount(2, $result->findings);
        self::assertSame(['one.example', 'two.example'], array_map(static fn (Finding $f): string => $f->target, $result->findings));
        self::assertSame([], $result->unreachable);
        self::assertSame([], $result->unscannable);
    }

    public function testATargetThatAnswersWithForbiddenIsUnscannableNotUnreachable(): void
    {
        $urls = [];
        $engine = self::engine([self::check()], static fn (): ResponseInterface => new Response(403, [], 'Forbidden'), $urls);

        $result = $engine->run(Config::fromArray([
            'targets' => ['https://one.example/'],
            'checks' => ['php_presence' => true],
        ]));

        self::assertSame([], $result->unreachable);
        self::assertCount(1, $result->unscannable);
        self::assertSame('one.example', $result->unscannable[0]['target']);
        self::assertSame(403, $result->unscannable[0]['status']);
        self::assertSame([], $result->findings);
    }

    public function testAnUnreachableTargetDoesNotStopTheOthers(): void
    {
        $urls = [];
        $engine = self::engine([self::check()], static function (RequestInterface $request): ResponseInterface|\Throwable {
            if (str_contains((string) $request->getUri(), 'broken.example')) {
                return new ConnectException('Connection refused', $request);
            }

            return new Response(200, [], 'ok');
        }, $urls);

        $result = $engine->run(Config::fromArray([
            'targets' => ['https://broken.example/', 'https://one.example/'],
            'checks' => ['php_presence' => true],
        ]));

        self::assertCount(1, $result->unreachable);
        self::assertSame('broken.example', $result->unreachable[0]['target']);
        self::assertNotSame('', $result->unreachable[0]['error']);
        self::assertSame([], $result->unscannable);
        self::assertCount(1, $result->findings);
        self::assertSame('one.example', $result->findings[0]->target);
    }

    public function testTheRootIsFetchedOnceAndReusedForTheAnalysis(): void
    {
        $check = new class implements Check {
            /** @var array<string, ResponseInterface> */
            public array $responses = [];

            public function id(): string
            {
                return 'php_presence';
            }

            public function paths(Target $target, ?ResponseInterface $baseline): array
            {
                return ['/', '/.env'];
            }

            public function analyze(Target $target, array $responses): array
            {
                $this->responses = $responses;

                return [];
            }
        };

        $urls = [];
        $engine = self::engine([$check], static fn (): ResponseInterface => new Response(200, [], 'ok'), $urls);

        $engine->run(Config::fromArray([
            'targets' => ['https://one.example/'],
            'checks' => ['php_presence' => true],
        ]));

        // The root is the baseline: it is not requested a second time.
        self::assertSame(['https://one.example/', 'https://one.example/.env'], $urls);

        self::assertArrayHasKey('/', $check->responses);
        self::assertArrayHasKey('/.env', $check->responses);
        self::assertSame(200, $check->responses['/']->getStatusCode());
    }

    public function testProgressIsReportedAsRequestsSettle(): void
    {
        $urls = [];
        $engine = self::engine([self::check(['/', '/.env'])], static fn (): ResponseInterface => new Response(200, [], 'ok'), $urls);

        $events = [];
        $engine->run(
            Config::fromArray([
                'targets' => ['https://one.example/', 'https://two.example/'],
                'checks' => ['php_presence' => true],
            ]),
            function (string $label, string $phase, int $done, int $total) use (&$events): void {
                $events[] = compact('label', 'phase', 'done', 'total');
            },
        );

        self::assertSame(['baseline', 'baseline', 'probe', 'probe', 'analyse', 'analyse'], array_column($events, 'phase'));
        self::assertSame(['one.example', 'two.example'], array_column(array_slice($events, 0, 2), 'label'));
        self::assertSame([1, 2], array_column(array_slice($events, 0, 2), 'done'));
        self::assertSame([2, 2], array_column(array_slice($events, 0, 2), 'total'));
        self::assertSame([1, 2], array_column(array_slice($events, 2, 2), 'done'));
        self::assertSame([2, 2], array_column(array_slice($events, 2, 2), 'total'));
    }

    public function testACheckThatIsNotEnabledIsNeverRun(): void
    {
        $disabled = new class implements Check {
            public bool $ran = false;

            public function id(): string
            {
                return 'php_version';
            }

            public function paths(Target $target, ?ResponseInterface $baseline): array
            {
                $this->ran = true;

                return [];
            }

            public function analyze(Target $target, array $responses): array
            {
                $this->ran = true;

                return [];
            }
        };

        $urls = [];
        $engine = self::engine([self::check(), $disabled], static fn (): ResponseInterface => new Response(200, [], 'ok'), $urls);

        $result = $engine->run(Config::fromArray([
            'targets' => ['https://one.example/'],
            'checks' => ['php_presence' => true],
        ]));

        self::assertFalse($disabled->ran, 'a check that is not enabled must never touch the target');
        self::assertCount(1, $result->findings);
    }

    /**
     * @param list<string> $paths
     */
    private static function check(array $paths = ['/']): Check
    {
        return new class ($paths) implements Check {
            /**
             * @param list<string> $paths
             */
            public function __construct(private readonly array $paths)
            {
            }

            public function id(): string
            {
                return 'php_presence';
            }

            public function paths(Target $target, ?ResponseInterface $baseline): array
            {
                return $this->paths;
            }

            public function analyze(Target $target, array $responses): array
            {
                return [new Finding(
                    id: 'php_presence',
                    title: 'PHP detected',
                    severity: Severity::Info,
                    target: $target->host(),
                    evidence: 'test',
                    exploit: 'test',
                    reproduce: ['step'],
                )];
            }
        };
    }

    /**
     * @param \Closure(RequestInterface): (ResponseInterface|\Throwable) $responder
     * @param list<Check>                                                     $checks
     * @param list<string>                                                    $urls    filled with every requested URL
     */
    private static function engine(array $checks, \Closure $responder, array &$urls): Engine
    {
        // A transport stub instead of the network: the engine is exercised
        // without a server, so the test is deterministic.
        $handler = function (RequestInterface $request, array $options) use ($responder, &$urls): PromiseInterface {
            $urls[] = (string) $request->getUri();
            $response = $responder($request);

            return $response instanceof \Throwable
                ? Create::rejectionFor($response)
                : Create::promiseFor($response);
        };

        $client = new Client(new GuzzleClient([
            'handler' => HandlerStack::create($handler),
            'http_errors' => false,
        ]), 0);

        // The pool drives the client, and the client is stubbed above, so the
        // CurlMultiHandler the pool is built with never carries a transfer.
        $pool = new Pool(new CurlMultiHandler(), $client);

        $byId = [];
        foreach ($checks as $check) {
            $byId[$check->id()] = $check;
        }

        return new Engine($pool, $client, new Registry($byId));
    }
}
