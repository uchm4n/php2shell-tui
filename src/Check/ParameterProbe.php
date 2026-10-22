<?php

declare(strict_types=1);

namespace Php2Scan\Check;

use Php2Scan\Crawler\Crawler;
use Php2Scan\Data\Reproduce;
use Php2Scan\Finding;
use Php2Scan\Http\Client;
use Php2Scan\Severity;
use Php2Scan\Target;
use Psr\Http\Message\ResponseInterface;

abstract class ParameterProbe implements Check
{
    /**
     * One check never sends more than this many proof-of-concept requests to a
     * single target, so a large crawl cannot turn into a flood.
     */
    private const MAX_PROBES = 60;

    /**
     * The subclasses inherit this constructor unchanged.
     *
     * @param null|\Closure(Target): array<string, list<string>> $parameterSource
     */
    public function __construct(
        protected readonly Reproduce $reproduce,
        protected readonly Client $client,
        protected readonly ?\Closure $parameterSource = null,
    ) {
    }

    public function id(): string
    {
        return $this->probeId();
    }

    public function paths(Target $target, ?ResponseInterface $baseline): array
    {
        // The crawler discovers the URLs to probe, so the engine has nothing to fetch.
        return [];
    }

    abstract protected function probeId(): string;

    abstract protected function probeTitle(): string;

    abstract protected function severity(): Severity;

    /**
     * The payloads to substitute into every parameter the crawler discovered.
     *
     * @return list<string>
     */
    abstract protected function payloads(string $marker): array;

    abstract protected function isConfirmed(
        ResponseInterface $baseline,
        ResponseInterface $mutated,
        string $mutatedUrl,
        string $marker,
    ): bool;

    abstract protected function evidence(ResponseInterface $baseline, ResponseInterface $mutated, string $mutatedUrl): string;

    abstract protected function exploit(string $mutatedUrl): string;

    public function analyze(Target $target, array $responses): array
    {
        $parameters = $this->parameterSource !== null
            ? ($this->parameterSource)($target)
            : (new Crawler($this->client))->parameters($target);

        // The angle brackets make HTML-escaping visible: a reflected marker is
        // proof only while it still contains the literal "<" and ">".
        $marker = '<php2scan' . bin2hex(random_bytes(4)) . '>';
        $probes = 0;

        foreach ($parameters as $url => $names) {
            if ($names === [] || $probes >= self::MAX_PROBES) {
                continue;
            }

            $baseline = $this->client->get($url, $target->requestHeaders());

            if ($baseline === null) {
                continue;
            }

            // Fetch the same URL twice. A page that differs from itself (a CSRF
            // token, a timestamp) would make any payload look like it changed the
            // response, so such a URL cannot be probed reliably.
            $again = $this->client->get($url, $target->requestHeaders());

            if ($again === null
                || $again->getStatusCode() !== $baseline->getStatusCode()
                || (string) $again->getBody() !== (string) $baseline->getBody()) {
                continue;
            }

            foreach ($names as $name) {
                foreach ($this->payloads($marker) as $payload) {
                    if ($probes >= self::MAX_PROBES) {
                        break 2;
                    }

                    $probes++;
                    $mutatedUrl = $this->applyPayload($url, $name, $payload);
                    $mutated = $this->client->get($mutatedUrl, $target->requestHeaders());

                    if ($mutated === null || !$this->isConfirmed($baseline, $mutated, $mutatedUrl, $marker)) {
                        continue;
                    }

                    // One finding per check per target; the finding names the URL
                    // and the parameter that carried the payload.
                    return [new Finding(
                        id: $this->probeId(),
                        title: $this->probeTitle(),
                        severity: $this->severity(),
                        target: $target->label(),
                        evidence: $this->evidence($baseline, $mutated, $mutatedUrl),
                        exploit: $this->exploit($mutatedUrl),
                        reproduce: $this->reproduce->steps($this->probeId(), $target->url, $target->label()),
                    )];
                }
            }
        }

        return [];
    }

    private function applyPayload(string $url, string $name, string $payload): string
    {
        $parts = parse_url($url);

        if ($parts === false || !isset($parts['host'])) {
            return $url;
        }

        $query = [];
        parse_str((string) ($parts['query'] ?? ''), $query);
        $query[$name] = $payload;

        return sprintf(
            '%s://%s%s%s%s',
            $parts['scheme'] ?? 'https',
            $parts['host'],
            isset($parts['port']) ? ':' . $parts['port'] : '',
            $parts['path'] ?? '/',
            '?' . http_build_query($query)
        );
    }
}
