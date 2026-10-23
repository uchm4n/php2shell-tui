<?php

declare(strict_types=1);

namespace Php2ShellTui\Http;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Promise\PromiseInterface;
use Psr\Http\Message\ResponseInterface;

final class Client
{
    public function __construct(
        private readonly GuzzleClient $guzzle,
        private readonly int $delayMs = 0,
    ) {
    }

    public function guzzle(): GuzzleClient
    {
        return $this->guzzle;
    }

    public function delayMs(): int
    {
        return $this->delayMs;
    }

    /**
     * @param array<string, string> $headers
     */
    public function getAsync(string $url, array $headers = [], int $delayMs = 0): PromiseInterface
    {
        // Holds the redirect response that was not followed, if any.
        $blocked = null;

        $options = [
            'http_errors' => false,
            'allow_redirects' => [
                'max' => 5,
                'strict' => false,
                'referer' => false,
                'track_redirects' => true,
                // A redirect that leaves the allowlisted host is not followed:
                // following it would contact a host the operator never listed.
                // Guzzle 8 ignores this callback's return value, so the chain
                // is stopped by throwing and the 3xx is restored below.
                'on_redirect' => function ($request, $response, $uri) use (&$blocked): bool {
                    $from = $request->getUri()->getHost();
                    $to = $uri->getHost();

                    if ($from !== '' && $to !== '' && strcasecmp($from, $to) !== 0) {
                        $blocked = $response;

                        throw new \RuntimeException(sprintf('Refusing to follow the redirect from "%s" to "%s".', $from, $to));
                    }

                    return true;
                },
            ],
        ];

        if ($headers !== []) {
            $options['headers'] = $headers;
        }

        $delay = max($this->delayMs, $delayMs);
        if ($delay > 0) {
            $options['delay'] = $delay;
        }

        return $this->guzzle
            ->requestAsync('GET', $url, $options)
            ->otherwise(function (\Throwable $e) use (&$blocked): ResponseInterface {
                if ($blocked !== null) {
                    return $blocked;
                }

                throw $e;
            });
    }

    /**
     * @param array<string, string> $headers
     * @param array<string, string> $fields
     */
    public function postAsync(string $url, array $headers, array $fields, bool $multipart = false): PromiseInterface
    {
        // Suppress 100-continue: the probe should not wait for an interim
        // response from a server that may not speak it correctly.
        $headers['Expect'] = '';

        $options = [
            'http_errors' => false,
            'allow_redirects' => false,
            'stream' => true,
            'headers' => $headers,
        ];

        if ($multipart) {
            $options['multipart'] = [];
            foreach ($fields as $name => $value) {
                $options['multipart'][] = [
                    'name' => (string) $name,
                    'contents' => (string) $value,
                ];
            }
        } else {
            $options['form_params'] = $fields;
        }

        if ($this->delayMs > 0) {
            $options['delay'] = $this->delayMs;
        }

        return $this->guzzle->requestAsync('POST', $url, $options);
    }

    /**
     * @param array<string, string> $headers
     * @param array<string, string> $fields
     */
    public function post(string $url, array $headers = [], array $fields = [], bool $multipart = false): ?ResponseInterface
    {
        try {
            return $this->postAsync($url, $headers, $fields, $multipart)->wait();
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * @param array<string, string> $headers
     */
    public function get(string $url, array $headers = []): ?ResponseInterface
    {
        try {
            return $this->getAsync($url, $headers)->wait();
        } catch (\Throwable) {
            return null;
        }
    }
}
