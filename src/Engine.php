<?php

declare(strict_types=1);

namespace Php2ShellTui;

use Php2ShellTui\Check\ProgressAware;
use Php2ShellTui\Check\Registry;
use Php2ShellTui\Http\Pool;
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

        // Phase 2 - prefetch every path every check asked for. The paths are
        // tracked per check so a check never analyses another check's probes.
        $requests = [];
        $requestIndex = [];
        $pathsByCheck = [];
        $controlIndex = [];
        $labels = [];

        foreach ($reachable as $index => $entry) {
            $target = $entry['target'];

            // The root is the baseline: it was fetched in phase 1 and is not
            // requested again.
            $seen = [self::normalise($target->url) => true];
            $hasProbe = false;

            foreach ($checks as $check) {
                $paths = array_values(array_unique($check->paths($target, $entry['baseline'])));
                $pathsByCheck[$index][$check->id()] = $paths;

                foreach ($paths as $path) {
                    if ($path !== '/') {
                        $hasProbe = true;
                    }

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

            // Two control paths prove whether this host serves one catch-all
            // page for unknown paths. They are only needed when a check probes
            // a path other than the baseline, and a target URL with a query
            // string cannot carry a reliable relative probe.
            if (!$hasProbe || parse_url($target->url, PHP_URL_QUERY) !== null) {
                continue;
            }

            for ($i = 0; $i < 2; $i++) {
                $path = '/php2shell-control-' . bin2hex(random_bytes(8));
                $url = $this->urlFor($target, $path);

                $controlIndex[$index][] = count($requests);
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
            $controlHash = self::controlHash($responses, $controlIndex[$index] ?? []);

            foreach ($checks as $check) {
                if ($check instanceof ProgressAware) {
                    $check->setProgress($onProgress, $onTick);
                }

                $perCheck = [];

                foreach ($pathsByCheck[$index][$check->id()] ?? [] as $path) {
                    if ($path === '/') {
                        // The baseline was already fetched in phase 1; reuse it
                        // rather than requesting every target's root again.
                        $perCheck['/'] = $entry['baseline'];
                        continue;
                    }

                    $position = $requestIndex[$index][$path] ?? null;
                    $response = $position === null ? null : ($responses[$position]['response'] ?? null);

                    if ($response === null) {
                        continue;
                    }

                    // A path that serves the same page as two random paths is
                    // the site's catch-all document, not an exposed file.
                    if ($controlHash !== null
                        && $response->getStatusCode() === 200
                        && self::bodyFingerprint((string) $response->getBody()) === $controlHash) {
                        continue;
                    }

                    $perCheck[$path] = $response;
                }

                foreach ($check->analyze($target, $perCheck) as $finding) {
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

    /**
     * The fingerprint of the site's catch-all page, or null when the two
     * control requests do not prove one exists.
     *
     * @param list<array{url: string, response: ResponseInterface|null, error: string|null}> $responses
     * @param list<int> $positions
     */
    private static function controlHash(array $responses, array $positions): ?string
    {
        if (count($positions) !== 2) {
            return null;
        }

        $fingerprints = [];

        foreach ($positions as $position) {
            $response = $responses[$position]['response'] ?? null;

            if ($response === null || $response->getStatusCode() !== 200) {
                return null;
            }

            $body = (string) $response->getBody();
            if (trim($body) === '') {
                return null;
            }

            $fingerprints[] = self::bodyFingerprint($body);
        }

        return $fingerprints[0] === $fingerprints[1] ? $fingerprints[0] : null;
    }

    /**
     * Whitespace-insensitive so a server that reformats the same page between
     * requests is still recognised as a catch-all.
     */
    private static function bodyFingerprint(string $body): string
    {
        $normalised = preg_replace('/\s+/', ' ', trim($body));

        return hash('sha256', $normalised ?? $body);
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
