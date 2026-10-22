<?php

declare(strict_types=1);

namespace Php2ShellTui\Check;

use Php2ShellTui\Data\Reproduce;
use Php2ShellTui\Data\Wordlists;
use Php2ShellTui\Finding;
use Php2ShellTui\Severity;
use Php2ShellTui\Target;
use Psr\Http\Message\ResponseInterface;

final class WebshellIndicators implements Check
{
    private const PRIMITIVES = '/\b(system|shell_exec|passthru|proc_open|popen|eval)\s*\(|\bbase64_decode\s*\(/i';

    private const INPUT = '/\$_(GET|POST|REQUEST|COOKIE)\b/i';

    public function __construct(
        private readonly Wordlists $wordlists,
        private readonly Reproduce $reproduce,
    ) {
    }

    public function id(): string
    {
        return 'webshell_indicators';
    }

    public function paths(Target $target, ?ResponseInterface $baseline): array
    {
        $directories = [''];
        foreach ($target->paths as $extra) {
            $directories[] = trim($extra, '/');
        }

        $paths = [];
        foreach ($directories as $directory) {
            foreach ($this->wordlists->webshellPaths() as $file) {
                $paths[] = '/' . ($directory === '' ? '' : $directory . '/') . $file;
            }
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
            if ($body === '') {
                continue;
            }

            if (preg_match(self::PRIMITIVES, $body) !== 1) {
                continue;
            }

            if (preg_match(self::INPUT, $body) !== 1) {
                continue;
            }

            $findings[] = new Finding(
                id: 'webshell-indicator',
                title: 'Possible webshell at ' . $path,
                severity: Severity::High,
                target: $target->label(),
                evidence: sprintf('HTTP 200 at %s, %d bytes, body contains a shell primitive and request input.', $path, strlen($body)),
                exploit: sprintf('Send a command to %s, e.g. curl "%s?c=id", and the server executes it.', $path, rtrim($target->url, '/') . $path),
                reproduce: $this->reproduce->steps('webshell-indicator', $target->url, $target->label(), ['path' => ltrim($path, '/')]),
            );
        }

        return $findings;
    }
}
