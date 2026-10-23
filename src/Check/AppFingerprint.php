<?php

declare(strict_types=1);

namespace Php2ShellTui\Check;

use Php2ShellTui\Data\Reproduce;
use Php2ShellTui\Finding;
use Php2ShellTui\Severity;
use Php2ShellTui\Target;
use Psr\Http\Message\ResponseInterface;

final class AppFingerprint implements Check
{
    private const PRODUCTS = [
        'WordPress' => ['/wp-includes/version.php', '/wp-login.php', '/wp-content/'],
        'Drupal'    => ['/core/CHANGELOG.txt', '/user/register', '/sites/default/files/'],
        'Joomla'    => ['/administrator/', '/language/en-GB/en-GB.xml', '/media/system/js/'],
        'Laravel'   => ['/telescope', '/_ignition/health-check', '/storage/logs/laravel.log'],
        'Symfony'   => ['/_profiler/', '/_wdt/', '/app_dev.php'],
        'Next.js'   => ['/_next/static/', '/__nextjs_original-stack-frame'],
    ];

    public function __construct(private readonly Reproduce $reproduce) {}

    public function id(): string
    {
        return 'app_fingerprint';
    }

    public function paths(Target $target, ?ResponseInterface $baseline): array
    {
        $paths = ['/'];

        foreach (self::PRODUCTS as $probes) {
            foreach ($probes as $probe) {
                $paths[] = $probe;
            }
        }

        return array_values(array_unique($paths));
    }

    public function analyze(Target $target, array $responses): array
    {
        $findings = [];
        $baseline = $responses['/'] ?? null;
        $body     = (string)$baseline?->getBody();

        foreach (self::PRODUCTS as $product => $probes) {
            $version = null;

            foreach ($probes as $probe) {
                $response = $responses[$probe] ?? null;
                if ($response === null || $response->getStatusCode() !== 200) {
                    continue;
                }

                $version = self::detectVersion($product, (string)$response->getBody()) ?? $version;
            }

            if ($product === 'WordPress'
                && $version === null
                && (self::references($target, $body, 'wp-content')
                    || self::references($target, $body, 'wp-includes')
                    || self::references($target, $body, 'wp-json'))) {
                $version = 'version not disclosed';
            }

            if ($product === 'Next.js'
                && $version === null
                && self::references($target, $body, '_next/static')) {
                $version = 'version not disclosed';
            }

            if ($version === null) {
                continue;
            }

            $findings[] = new Finding(
                id: 'app-' . strtolower($product),
                title: $product . ' detected',
                severity: Severity::Info,
                target: $target->label(),
                evidence: sprintf('%s (%s).', $product, $version),
                exploit: 'Check the running version against the upstream security advisories for ' . $product . ' - the scanner does not carry a CMS advisory database.',
                reproduce: $this->reproduce->steps('app-fingerprint', $target->url, $target->label()),
            );
        }

        return $findings;
    }

    /**
     * Does the page reference the product path on its own origin?
     *
     * A link to an external CDN that happens to contain "/wp-content/" is not
     * evidence that this host runs WordPress.
     */
    private static function references(Target $target, string $body, string $path): bool
    {
        $needle = strtolower(trim($path, '/'));
        $hosts = [];

        foreach ([$target->host(), $target->vhost] as $host) {
            if ($host !== null && $host !== '') {
                $hosts[] = strtolower($host);
            }
        }

        if (preg_match_all('/\b(?:src|href|action)\s*=\s*(["\'])(.*?)\1/is', $body, $matches) === false) {
            return false;
        }

        foreach ($matches[2] as $value) {
            $url = html_entity_decode(trim($value), ENT_QUOTES | ENT_HTML5);

            if ($url === ''
                || str_starts_with($url, '#')
                || str_starts_with($url, 'data:')
                || str_starts_with($url, 'javascript:')) {
                continue;
            }

            if (str_starts_with($url, '//')) {
                $url = 'https:' . $url;
            }

            $parts = parse_url($url);

            if ($parts === false) {
                continue;
            }

            if (isset($parts['host']) && !in_array(strtolower($parts['host']), $hosts, true)) {
                continue;
            }

            $pathPart = strtolower($parts['path'] ?? $url);

            if (str_contains($pathPart, $needle)) {
                return true;
            }
        }

        return false;
    }

    private static function detectVersion(string $product, string $body): ?string
    {
        if ($product === 'WordPress' && preg_match("/\\\$wp_version\s*=\s*'([^']+)'/", $body, $m) === 1) {
            return $m[1];
        }

        if ($product === 'Drupal' && preg_match('/Drupal (\d+\.\d+)/i', $body, $m) === 1) {
            return $m[1];
        }

        return null;
    }
}
