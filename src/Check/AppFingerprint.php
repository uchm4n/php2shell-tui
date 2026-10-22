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

            if ($product === 'WordPress' && preg_match('/wp-content|wp-includes/i', $body) === 1 && $version === null) {
                $version = 'version not disclosed';
            }

            if ($product === 'Next.js' && preg_match('/\/_next\/static\//i', $body) === 1 && $version === null) {
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
