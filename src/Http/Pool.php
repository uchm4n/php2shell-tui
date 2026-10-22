<?php

declare(strict_types=1);

namespace Php2Scan\Http;

use GuzzleHttp\Handler\CurlMultiHandler;
use Psr\Http\Message\ResponseInterface;

final class Pool
{
    public function __construct(
        private readonly CurlMultiHandler $handler,
        private readonly Client $client,
    ) {
    }

    public function handler(): CurlMultiHandler
    {
        return $this->handler;
    }

    /**
     * @param list<array{url: string, headers: array<string, string>}> $requests
     * @param null|callable(string, ResponseInterface|null, string|null): void $onSettled
     * @return list<array{url: string, response: ResponseInterface|null, error: string|null}>
     */
    public function run(array $requests, ?callable $onSettled = null): array
    {
        if ($requests === []) {
            return [];
        }

        $results = [];
        $promises = [];

        // Requests to the same host are spaced by the client delay so a scan
        // never hammers a single origin.
        $perHostCounter = [];

        foreach ($requests as $index => $request) {
            // Prefilled so the result list keeps the request order even if a
            // request never settles.
            $results[$index] = ['url' => $request['url'], 'response' => null, 'error' => null];

            $host = (string) parse_url($request['url'], PHP_URL_HOST);
            $sequence = $perHostCounter[$host] ?? 0;
            $perHostCounter[$host] = $sequence + 1;

            $promises[] = $this->client
                ->getAsync($request['url'], $request['headers'], $sequence * $this->client->delayMs())
                ->then(
                    function (ResponseInterface $response) use (&$results, $index, $request, $onSettled): void {
                        $results[$index] = ['url' => $request['url'], 'response' => $response, 'error' => null];
                        if ($onSettled !== null) {
                            $onSettled($request['url'], $response, null);
                        }
                    },
                    function (\Throwable $e) use (&$results, $index, $request, $onSettled): void {
                        $results[$index] = ['url' => $request['url'], 'response' => null, 'error' => $e->getMessage()];
                        if ($onSettled !== null) {
                            $onSettled($request['url'], null, $e->getMessage());
                        }
                    }
                );
        }

        // Waiting on a promise drives the cURL multi handler until that
        // transfer settles, and every other transfer keeps running in the
        // meantime. The handler's tick() alone cannot be used: it does not
        // block while a transfer waits for its delay to elapse.
        foreach ($promises as $promise) {
            $promise->wait();
        }

        ksort($results);

        return array_values($results);
    }
}
