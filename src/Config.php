<?php

declare(strict_types=1);

namespace Php2ShellTui;

final class Config
{
    public const CHECKS = [
        'php_presence',
        'php_version',
        'php2shell',
        'sensitive_files',
        'security_headers',
        'tls',
        'app_fingerprint',
        'webshell_indicators',
        'open_ports',
        'injection',
        'sql_injection',
        'reflected_xss',
        'local_file_inclusion',
    ];

    public const FORMATS = ['tui', 'text', 'json', 'markdown'];

    /**
     * @param list<Target>        $targets
     * @param array<string, bool> $checks
     */
    public function __construct(
        public readonly array $targets,
        public readonly array $checks,
        public readonly int $concurrency,
        public readonly int $timeout,
        public readonly int $connectTimeout,
        public readonly int $delayMs,
        public readonly string $userAgent,
        public readonly Severity $minSeverity,
        public readonly string $format,
        public readonly string $reportDir,
        public readonly int $pocTimeout,
        public readonly int $pocMaxWorkers,
    ) {
    }

    public static function fromFile(string $path): self
    {
        if (!is_file($path)) {
            throw new \InvalidArgumentException(sprintf('Config file "%s" does not exist.', $path));
        }

        $parsed = \Symfony\Component\Yaml\Yaml::parseFile($path);

        if (!is_array($parsed)) {
            throw new \InvalidArgumentException(sprintf('Config file "%s" is empty or malformed.', $path));
        }

        return self::fromArray($parsed);
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        $targets = self::parseTargets($data['targets'] ?? []);
        $checks = self::parseChecks($data['checks'] ?? []);
        $options = is_array($data['options'] ?? null) ? $data['options'] : [];
        $output = is_array($data['output'] ?? null) ? $data['output'] : [];

        $format = (string) ($output['format'] ?? 'tui');
        if (!in_array($format, self::FORMATS, true)) {
            throw new \InvalidArgumentException(sprintf('Unknown output format "%s"; expected one of %s.', $format, implode(', ', self::FORMATS)));
        }

        $minSeverity = Severity::fromName((string) ($options['min_severity'] ?? 'medium'));

        return new self(
            targets: $targets,
            checks: $checks,
            concurrency: max(1, (int) ($options['concurrency'] ?? 8)),
            timeout: max(1, (int) ($options['timeout'] ?? 10)),
            connectTimeout: max(1, (int) ($options['connect_timeout'] ?? 5)),
            delayMs: max(0, (int) ($options['delay_ms'] ?? 100)),
            userAgent: (string) ($options['user_agent'] ?? sprintf('php2shell-tui/%s', Application::VERSION)),
            minSeverity: $minSeverity,
            format: $format,
            reportDir: (string) ($output['report_dir'] ?? './reports'),
            pocTimeout: max(1, (int) ($options['poc_timeout'] ?? 180)),
            pocMaxWorkers: max(1, (int) ($options['poc_max_workers'] ?? 150)),
        );
    }

    public function checkEnabled(string $id): bool
    {
        return $this->checks[$id] ?? false;
    }

    /**
     * @return list<string>
     */
    public function enabledChecks(): array
    {
        $enabled = [];

        foreach (self::CHECKS as $id) {
            if ($this->checkEnabled($id)) {
                $enabled[] = $id;
            }
        }

        return $enabled;
    }

    /**
     * @param mixed $raw
     * @return list<Target>
     */
    private static function parseTargets(mixed $raw): array
    {
        if (!is_array($raw) || $raw === []) {
            throw new \InvalidArgumentException('Config must contain a non-empty "targets" list.');
        }

        $targets = [];

        foreach ($raw as $entry) {
            if (is_string($entry)) {
                $entry = ['url' => $entry];
            }

            if (!is_array($entry) || !isset($entry['url']) || !is_string($entry['url'])) {
                throw new \InvalidArgumentException('Each target must be a URL string or a map with a "url" key.');
            }

            $url = $entry['url'];
            if (filter_var($url, FILTER_VALIDATE_URL) === false) {
                throw new \InvalidArgumentException(sprintf('Target "%s" is not a valid URL.', $url));
            }

            $targets[] = new Target(
                url: $url,
                vhost: self::optionalHeader($entry, 'vhost'),
                paths: array_values(array_map('strval', (array) ($entry['paths'] ?? []))),
                staging: self::optionalBool($entry, 'staging'),
                postPath: self::sameOriginPath($entry, 'post_path'),
                pocProfile: self::localProfile($entry),
            );
        }

        return $targets;
    }

    /**
     * @param array<string, mixed> $entry
     */
    private static function sameOriginPath(array $entry, string $key): ?string
    {
        if (!array_key_exists($key, $entry)) {
            return null;
        }

        $value = $entry[$key];

        if (!is_string($value)
            || $value === ''
            || $value[0] !== '/'
            || str_starts_with($value, '//')
            || str_contains($value, '://')
            || preg_match('/[\x00-\x20\x7F]/', $value) === 1) {
            throw new \InvalidArgumentException(sprintf(
                'Target option "%s" must be an absolute same-origin path starting with "/" and contain no whitespace or control characters.',
                $key,
            ));
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $entry
     */
    private static function optionalBool(array $entry, string $key): bool
    {
        if (!array_key_exists($key, $entry)) {
            return false;
        }

        if (!is_bool($entry[$key])) {
            throw new \InvalidArgumentException(sprintf('Target option "%s" must be a boolean.', $key));
        }

        return $entry[$key];
    }

    /**
     * @param array<string, mixed> $entry
     */
    private static function optionalHeader(array $entry, string $key): ?string
    {
        if (!array_key_exists($key, $entry)) {
            return null;
        }

        $value = $entry[$key];

        if (!is_string($value)
            || trim($value) === ''
            || preg_match('/[\x00-\x20\x7F]/', $value) === 1) {
            throw new \InvalidArgumentException(sprintf('Target option "%s" must be a safe header value.', $key));
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $entry
     */
    private static function localProfile(array $entry): ?string
    {
        if (!array_key_exists('poc_profile', $entry)) {
            return null;
        }

        $value = $entry['poc_profile'];

        if (!is_string($value)
            || trim($value) === ''
            || str_contains($value, '://')
            || preg_match('/[\x00-\x1F\x7F]/', $value) === 1) {
            throw new \InvalidArgumentException('Target option "poc_profile" must be a local profile ID or path, not a URL.');
        }

        return $value;
    }

    /**
     * @return array<string, bool>
     */
    private static function parseChecks(mixed $raw): array
    {
        if (!is_array($raw)) {
            $raw = [];
        }

        foreach (array_keys($raw) as $id) {
            if (!in_array($id, self::CHECKS, true)) {
                throw new \InvalidArgumentException(sprintf('unknown check "%s" in config; known checks are %s.', $id, implode(', ', self::CHECKS)));
            }
        }

        $checks = [];
        foreach (self::CHECKS as $id) {
            if (!array_key_exists($id, $raw)) {
                // The active PHP2Shell check is on by default; it still sends
                // no POST requests unless --verify is passed.
                $checks[$id] = $id === 'php2shell';
                continue;
            }

            if (!is_bool($raw[$id])) {
                throw new \InvalidArgumentException(sprintf('Check "%s" must be a boolean.', $id));
            }

            $checks[$id] = $raw[$id];
        }

        // The single `injection` toggle switches on the three verification checks.
        if ($checks['injection'] ?? false) {
            $checks['sql_injection'] = true;
            $checks['reflected_xss'] = true;
            $checks['local_file_inclusion'] = true;
        }

        return $checks;
    }
}
