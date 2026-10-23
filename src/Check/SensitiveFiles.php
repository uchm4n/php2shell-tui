<?php

declare(strict_types=1);

namespace Php2ShellTui\Check;

use Php2ShellTui\Data\Reproduce;
use Php2ShellTui\Data\Wordlists;
use Php2ShellTui\Finding;
use Php2ShellTui\Severity;
use Php2ShellTui\Target;
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

    private const SECRET_PATTERN = '/\b(?:APP_KEY|DB_PASSWORD|DB_PASS|SECRET(?:_KEY)?|PRIVATE KEY|api[_-]?key|access[_-]?token)\b\s*[:=]/i';

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
        // Target "paths" are extra webshell directories, not sensitive files.
        return array_map(static fn (string $p): string => '/' . ltrim($p, '/'), $this->wordlists->sensitivePaths());
    }

    public function analyze(Target $target, array $responses): array
    {
        $findings = [];

        foreach ($responses as $path => $response) {
            // The root document is the site itself, not an exposed file.
            if ($path === '/') {
                continue;
            }

            if ($response->getStatusCode() !== 200) {
                continue;
            }

            $body = (string) $response->getBody();
            if (trim($body) === '') {
                continue;
            }

            $relative = ltrim($path, '/');

            // A 200 is not proof: a catch-all page, a WAF page or a custom 404
            // can answer every path. Require the body to look like the file the
            // path claims to be.
            if (!self::matchesSignature($relative, $body)) {
                continue;
            }

            $severity = self::severityFor($relative);
            $matched = preg_match_all(self::SECRET_PATTERN, $body, $matches) > 0
                ? 'contains credential-looking keys (' . implode(', ', array_unique($matches[0])) . ')'
                : 'matches the expected file format';

            $findings[] = new Finding(
                id: 'sensitive-file-' . str_replace('/', '-', ltrim($relative, '.')),
                title: 'Exposed ' . $relative,
                severity: $severity,
                target: $target->label(),
                evidence: sprintf(
                    'HTTP 200, %d bytes, %s.',
                    strlen($body),
                    $matched
                ),
                exploit: sprintf('Request %s and read whatever it returns - it is served publicly.', rtrim($target->url, '/') . '/' . $relative),
                reproduce: $this->reproduce->steps('sensitive-file', $target->url, $target->label(), ['path' => $relative]),
            );
        }

        return $findings;
    }

    /**
     * The body must carry the marker of the claimed file type. This is what
     * separates a leaked file from a generic page that answers 200.
     */
    private static function matchesSignature(string $relative, string $body): bool
    {
        $json = static function (array $keys) use ($body): bool {
            $decoded = json_decode($body, true);

            if (!is_array($decoded)) {
                return false;
            }

            foreach ($keys as $key) {
                if (array_key_exists($key, $decoded)) {
                    return true;
                }
            }

            return false;
        };

        return match (true) {
            $relative === '.env',
            str_starts_with($relative, '.env.') => preg_match('/^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.]*\s*=/m', $body) === 1,
            $relative === '.git/config' => preg_match('/^\s*\[(?:core|remote|branch)\]/mi', $body) === 1,
            $relative === '.git/HEAD' => preg_match('/^(?:ref:\s+refs\/|[0-9a-f]{40})/mi', $body) === 1,
            $relative === 'composer.json' => $json(['name', 'require', 'require-dev', 'autoload', 'config']),
            $relative === 'composer.lock' => $json(['packages', 'packages-dev', 'content-hash']),
            $relative === 'package.json' => $json(['name', 'dependencies', 'devDependencies', 'scripts']),
            $relative === 'package-lock.json' => $json(['lockfileVersion', 'packages', 'dependencies']),
            $relative === '.htaccess' => preg_match('/^\s*(?:RewriteEngine|RewriteRule|Options|Header|AuthType|Require|Deny|Allow|Order|<IfModule)/mi', $body) === 1,
            $relative === '.DS_Store' => str_starts_with($body, "\x00\x00\x00\x01Bud1"),
            $relative === 'phpinfo.php',
            $relative === 'info.php' => preg_match('/PHP Version\s+\d/i', $body) === 1,
            $relative === 'server-status' => preg_match('/Apache Server Status|Server Version:/i', $body) === 1,
            $relative === 'server-info' => preg_match('/Apache Server Information|Server Settings/i', $body) === 1,
            $relative === 'wp-config.php.bak' => preg_match('/DB_NAME|DB_PASSWORD|<\?php/i', $body) === 1,
            $relative === 'backup.zip' => str_starts_with($body, "PK\x03\x04") || str_starts_with($body, "PK\x05\x06"),
            $relative === 'dump.sql' => preg_match('/-- MySQL dump|PostgreSQL database dump|CREATE TABLE|INSERT INTO/i', $body) === 1,
            $relative === '.aws/credentials' => preg_match('/aws_access_key_id|aws_secret_access_key|^\s*\[[^\]]+\]/mi', $body) === 1,
            $relative === '.npmrc' => preg_match('/registry\s*=|_authToken\s*=/i', $body) === 1,
            $relative === 'Dockerfile' => preg_match('/^\s*FROM\s+\S+/mi', $body) === 1,
            $relative === 'adminer.php' => preg_match('/\badminer\b/i', $body) === 1,
            $relative === 'phpmyadmin/' => preg_match('/\bphpMyAdmin\b/i', $body) === 1,
            $relative === 'id_rsa' => preg_match('/-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/', $body) === 1,
            default => !self::looksLikeHtml($body),
        };
    }

    private static function looksLikeHtml(string $body): bool
    {
        return preg_match('/^\s*(?:<!doctype\s+html|<html|<\?xml[^>]*>\s*<html)/i', $body) === 1;
    }

    private static function severityFor(string $relative): Severity
    {
        if (str_ends_with($relative, '.bak')) {
            return Severity::High;
        }

        foreach (self::HIGH as $needle) {
            if ($relative === $needle) {
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
