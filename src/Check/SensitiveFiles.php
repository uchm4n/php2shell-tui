<?php

declare(strict_types=1);

namespace Php2Scan\Check;

use Php2Scan\Data\Reproduce;
use Php2Scan\Data\Wordlists;
use Php2Scan\Finding;
use Php2Scan\Severity;
use Php2Scan\Target;
use Psr\Http\Message\ResponseInterface;

final class SensitiveFiles implements Check
{
    private const HIGH = [
        '.env', '.env.local', '.env.production', '.git/config', '.git/HEAD',
        '.aws/credentials', 'id_rsa', '.npmrc', 'backup.zip', 'dump.sql',
        'adminer.php', 'phpmyadmin/',
    ];

    private const MEDIUM = [
        'composer.json', 'composer.lock', 'package.json', 'package-lock.json',
        '.htaccess', 'phpinfo.php', 'info.php', 'server-status', 'server-info',
    ];

    private const LOW = ['Dockerfile', '.dockerignore'];

    private const SECRET_PATTERN = '/(APP_KEY|DB_PASSWORD|SECRET|TOKEN|PASSWORD|PRIVATE KEY|api[_-]?key)/i';

    public function __construct(
        private readonly Wordlists $wordlists,
        private readonly Reproduce $reproduce,
    ) {
    }

    public function id(): string
    {
        return 'sensitive_files';
    }

    public function paths(Target $target, ?ResponseInterface $baseline): array
    {
        $paths = array_map(static fn (string $p): string => '/' . ltrim($p, '/'), $this->wordlists->sensitivePaths());

        foreach ($target->paths as $extra) {
            $paths[] = '/' . trim($extra, '/');
        }

        return array_values(array_unique($paths));
    }

    public function analyze(Target $target, array $responses): array
    {
        $findings = [];

        foreach ($responses as $path => $response) {
            if ($response->getStatusCode() !== 200) {
                continue;
            }

            $body = (string) $response->getBody();
            if (trim($body) === '') {
                continue;
            }

            $relative = ltrim($path, '/');
            $severity = self::severityFor($relative);
            $matched = preg_match_all(self::SECRET_PATTERN, $body, $matches) > 0
                ? 'contains credential-looking keys (' . implode(', ', array_unique($matches[0])) . ')'
                : 'no credential-looking keys matched';

            $findings[] = new Finding(
                id: 'sensitive-file-' . str_replace('/', '-', $relative),
                title: 'Exposed ' . $relative,
                severity: $severity,
                target: $target->label(),
                evidence: sprintf(
                    'HTTP 200, %d bytes, %s.',
                    strlen($body),
                    $matched
                ),
                exploit: sprintf('Request %s and read whatever it returns - it is served publicly.', $target->url . '/' . $relative),
                reproduce: $this->reproduce->steps('sensitive-file', $target->url, $target->label(), ['path' => $relative]),
            );
        }

        return $findings;
    }

    private static function severityFor(string $relative): Severity
    {
        foreach (self::HIGH as $needle) {
            if ($relative === $needle || str_ends_with($relative, '.bak')) {
                return Severity::High;
            }
        }

        if (in_array($relative, self::MEDIUM, true)) {
            return Severity::Medium;
        }

        if (in_array($relative, self::LOW, true)) {
            return Severity::Low;
        }

        return Severity::Medium;
    }
}
