<?php

declare(strict_types=1);

namespace Php2ShellTui\Crawler;

use Php2ShellTui\Http\Client;
use Php2ShellTui\Target;
use Psr\Http\Message\ResponseInterface;
use Symfony\Component\DomCrawler\Crawler as DomCrawler;

final class Crawler
{
    private const MAX_PAGES = 50;

    public function __construct(
        private readonly Client $client,
        private readonly int $depth = 1,
    ) {
    }

    /**
     * @param array<string, ResponseInterface> $pages
     * @return array<string, list<string>> absolute URL => discovered parameter names
     */
    public function parameters(Target $target, array $pages = []): array
    {
        // A bare origin gets the trailing slash; a target that already carries
        // a path or a query string is used as given.
        $start = parse_url($target->url, PHP_URL_PATH) === null
            && parse_url($target->url, PHP_URL_QUERY) === null
            ? rtrim($target->url, '/') . '/'
            : $target->url;
        $queue = [$start];
        $hops = [$start => 0];
        $fetched = [];
        $parameters = [];

        while ($queue !== [] && count($fetched) < self::MAX_PAGES) {
            $url = array_shift($queue);

            if (isset($fetched[$url])) {
                continue;
            }
            $fetched[$url] = true;

            $response = $pages[$url] ?? $this->client->get($url, $target->requestHeaders());
            if ($response === null || $response->getStatusCode() >= 400) {
                continue;
            }

            $dom = new DomCrawler((string) $response->getBody(), $target->url);

            $query = [];
            parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
            foreach (array_keys($query) as $name) {
                $this->add($parameters, $url, (string) $name);
            }

            // DomCrawler's CSS filter() needs symfony/css-selector, which this
            // project does not depend on; XPath is built in.
            foreach ($dom->filterXPath('//form') as $formNode) {
                // DomCrawler iterates DOMElement nodes. Wrapping each form keeps its
                // inputs attached to that form; filtering $dom would return every
                // input on the page for every form.
                $form = new DomCrawler($formNode);
                $action = $formNode->getAttribute('action');
                $absolute = $action === '' ? $url : $this->absolute($action, $url);

                if ($absolute === null) {
                    continue;
                }

                foreach ($form->filterXPath('.//input | .//select | .//textarea') as $input) {
                    $name = $input->getAttribute('name');
                    if ($name !== '') {
                        $this->add($parameters, $absolute, $name);
                    }
                }
            }

            if (($hops[$url] ?? 0) >= $this->depth) {
                continue;
            }

            foreach ($dom->filterXPath('//a[@href]') as $link) {
                $absolute = $this->absolute($link->getAttribute('href'), $url);

                if ($absolute === null || isset($hops[$absolute])) {
                    continue;
                }

                $hops[$absolute] = ($hops[$url] ?? 0) + 1;
                $queue[] = $absolute;
            }
        }

        return $parameters;
    }

    /**
     * @param array<string, list<string>> $parameters
     */
    private function add(array &$parameters, string $url, string $name): void
    {
        $parameters[$url] ??= [];

        if (!in_array($name, $parameters[$url], true)) {
            $parameters[$url][] = $name;
        }
    }

    private function absolute(string $href, string $current): ?string
    {
        if ($href === ''
            || str_starts_with($href, '#')
            || str_starts_with($href, 'mailto:')
            || str_starts_with($href, 'javascript:')) {
            return null;
        }

        $parts = parse_url($href);

        if ($parts === false) {
            return null;
        }

        if (isset($parts['host'])) {
            // Same host only: the crawler must never contact a host the operator
            // did not allowlist.
            if ($parts['host'] !== parse_url($current, PHP_URL_HOST)) {
                return null;
            }

            return sprintf(
                '%s://%s%s%s%s',
                $parts['scheme'] ?? parse_url($current, PHP_URL_SCHEME) ?? 'https',
                $parts['host'],
                isset($parts['port']) ? ':' . $parts['port'] : '',
                $parts['path'] ?? '/',
                isset($parts['query']) ? '?' . $parts['query'] : ''
            );
        }

        $base = parse_url($current);
        $scheme = $base['scheme'] ?? 'https';
        $host = $base['host'] ?? '';
        $port = isset($base['port']) ? ':' . $base['port'] : '';

        if (str_starts_with($href, '/')) {
            return sprintf('%s://%s%s%s', $scheme, $host, $port, $href);
        }

        $path = $base['path'] ?? '/';
        $directory = rtrim(str_replace('\\', '/', dirname($path)), '/');

        return sprintf('%s://%s%s%s/%s', $scheme, $host, $port, $directory, $href);
    }
}
