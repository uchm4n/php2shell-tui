<?php

declare(strict_types=1);

namespace Php2Scan;

use Php2Scan\Check\Registry;
use Php2Scan\Http\Pool;
use Psr\Http\Message\ResponseInterface;

final class Engine
{
    /**
     * A baseline that answers with one of these is behind a WAF, a proxy or a
     * rate limiter: the target cannot be probed further.
     */
    private const UNSCANNABLE_STATUSES = [403, 407, 429, 503];

    public function __construct(
        private readonly Pool $pool,
        private readonly Registry $registry,
    ) {
    }

    public function run(Config $config, ?callable $onProgress = null, ?callable $onTick = null): ScanResult
    {
        $started = microtime(true);

        $checks = $this->registry->enabled($config);
        $findings = [];
        $unreachable = [];
        $unscannable = [];

        // Phase 1 - baseline: one request per target, all of them in flight
        // at the same time.
        $baselineRequests = [];
        $labels = [];

        foreach ($config->targets as $target) {
            $baselineRequests[] = ['url' => $target->url, 'headers' => $target->requestHeaders()];
            $labels[$target->url] ??= $target->label();
        }

        $baselines = $this->pool->run(
            $baselineRequests,
            $this->progress($onProgress, $labels, 'baseline', count($baselineRequests)),
            $onTick,
        );

        $reachable = [];

        foreach ($config->targets as $index => $target) {
            $response = $baselines[$index]['response'] ?? null;

            if ($response === null) {
                $unreachable[] = [
                    'target' => $target->label(),
                    'error' => $baselines[$index]['error'] ?? 'unknown error',
                ];
                continue;
            }

            if (in_array($response->getStatusCode(), self::UNSCANNABLE_STATUSES, true)) {
                $unscannable[] = ['target' => $target->label(), 'status' => $response->getStatusCode()];
                continue;
            }

            $reachable[$index] = ['target' => $target, 'baseline' => $response];
        }

        // Phase 2 - prefetch every path every check asked for.
        $requests = [];
        $requestIndex = [];
        $labels = [];

        foreach ($reachable as $index => $entry) {
            $target = $entry['target'];
            $paths = [];

            foreach ($checks as $check) {
                foreach ($check->paths($target, $entry['baseline']) as $path) {
                    $paths[] = $path;
                }
            }

            // The root is the baseline: it was fetched in phase 1 and is not
            // requested again.
            $seen = [self::normalise($target->url) => true];

            foreach (array_unique($paths) as $path) {
                $url = $this->urlFor($target, $path);

                if (isset($seen[self::normalise($url)])) {
                    continue;
                }
                $seen[self::normalise($url)] = true;

                $requestIndex[$index][$path] = count($requests);
                $requests[] = ['url' => $url, 'headers' => $target->requestHeaders()];
                $labels[$url] ??= $target->label();
            }
        }

        $responses = $this->pool->run(
            $requests,
            $this->progress($onProgress, $labels, 'probe', count($requests)),
            $onTick,
        );

        // Phase 3 - analyse.
        $analysed = 0;

        foreach ($reachable as $index => $entry) {
            $target = $entry['target'];
            $perTarget = [];

            // The baseline was already fetched in phase 1; reuse it rather than
            // requesting every target's root a second time.
            $perTarget['/'] = $entry['baseline'];

            foreach ($requestIndex[$index] ?? [] as $path => $position) {
                $response = $responses[$position]['response'] ?? null;
                if ($response !== null) {
                    $perTarget[$path] = $response;
                }
            }

            foreach ($checks as $check) {
                foreach ($check->analyze($target, $perTarget) as $finding) {
                    $findings[] = $finding;
                }
            }

            $analysed++;
            if ($onProgress !== null) {
                $onProgress($target->label(), 'analyse', $analysed, count($reachable));
            }
        }

        return new ScanResult($findings, $unreachable, $unscannable, microtime(true) - $started);
    }

    private function urlFor(Target $target, string $path): string
    {
        if (str_starts_with($path, 'http://') || str_starts_with($path, 'https://')) {
            // Checks are meant to return relative paths. An absolute URL is only
            // honoured when it stays on the allowlisted host, so a check can never
            // widen the scope the operator chose.
            if (parse_url($path, PHP_URL_HOST) !== parse_url($target->url, PHP_URL_HOST)) {
                throw new \InvalidArgumentException(sprintf(
                    'Check returned "%s", which is not on the target host "%s".',
                    $path,
                    (string) parse_url($target->url, PHP_URL_HOST)
                ));
            }

            return $path;
        }

        return rtrim($target->url, '/') . '/' . ltrim($path, '/');
    }

    private static function normalise(string $url): string
    {
        return rtrim($url, '/');
    }

    /**
     * Reports every settled request of a phase, so a caller can render live
     * progress instead of waiting for the phase to end.
     *
     * @param array<string, string> $labels request URL => target label
     * @return null|callable(string, ResponseInterface|null, string|null): void
     */
    private function progress(?callable $onProgress, array $labels, string $phase, int $total): ?callable
    {
        if ($onProgress === null) {
            return null;
        }

        $done = 0;

        return function (string $url, ?ResponseInterface $response, ?string $error) use ($onProgress, $labels, $phase, $total, &$done): void {
            $onProgress($labels[$url] ?? 'all', $phase, ++$done, $total);
        };
    }
}
