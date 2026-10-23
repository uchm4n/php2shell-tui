<?php

declare(strict_types=1);

namespace Php2ShellTui\Check;

use Php2ShellTui\Data\Reproduce;
use Php2ShellTui\Finding;
use Php2ShellTui\Severity;
use Php2ShellTui\Target;
use Psr\Http\Message\ResponseInterface;

final class PhpDetection implements Check
{
    public function __construct(private readonly Reproduce $reproduce)
    {
    }

    public function id(): string
    {
        return 'php_presence';
    }

    public function paths(Target $target, ?ResponseInterface $baseline): array
    {
        return ['/'];
    }

    public function analyze(Target $target, array $responses): array
    {
        $baseline = $responses['/'] ?? null;
        $signals = $baseline === null ? [] : self::signals($baseline);

        if ($signals === []) {
            return [new Finding(
                id: 'php_presence',
                title: 'No PHP signal detected',
                severity: Severity::Info,
                target: $target->label(),
                evidence: 'No PHP-specific X-Powered-By header, no PHP in the Server header, no PHPSESSID cookie, and no PHP body marker.',
                exploit: 'No PHP signal; if PHP runs behind a proxy or hides its headers, verify with server access or a full proof.',
                reproduce: $this->reproduce->steps('php_presence', $target->url, $target->label()),
            )];
        }

        return [new Finding(
            id: 'php_presence',
            title: 'PHP signal detected',
            severity: Severity::Info,
            target: $target->label(),
            evidence: 'Signals: ' . implode(', ', $signals) . '.',
            exploit: 'Confirm the runtime version on the host with "php -v"; the branch fixes are 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12, or a vendor backport.',
            reproduce: $this->reproduce->steps('php_presence', $target->url, $target->label()),
        )];
    }

    /**
     * PHP-specific header signals. This never reads the body, so it is safe to
     * use after another check has consumed the response stream.
     *
     * @return list<string>
     */
    public static function headerSignals(ResponseInterface $response): array
    {
        $signals = [];

        $poweredBy = $response->getHeaderLine('X-Powered-By');
        if ($poweredBy !== '' && preg_match('/\bPHP\b/i', $poweredBy) === 1) {
            $signals[] = 'X-Powered-By: ' . $poweredBy;
        }

        $server = $response->getHeaderLine('Server');
        if ($server !== '' && preg_match('/\bPHP\/(\d+\.\d+(?:\.\d+)?)/i', $server, $m) === 1) {
            $signals[] = 'Server: ' . $server;
        }

        foreach ($response->getHeader('Set-Cookie') as $cookie) {
            if (str_starts_with($cookie, 'PHPSESSID')) {
                $signals[] = 'Set-Cookie: PHPSESSID';
                break;
            }
        }

        return $signals;
    }

    /**
     * @return list<string>
     */
    public static function signals(ResponseInterface $response): array
    {
        $signals = self::headerSignals($response);

        $body = $response->getBody();
        if ($body->isSeekable()) {
            $body->rewind();
        }

        $content = (string) $body;

        if ($body->isSeekable()) {
            $body->rewind();
        }

        if ($content !== '' && preg_match('/Powered by PHP|<meta[^>]+generator[^>]+PHP/i', $content) === 1) {
            $signals[] = 'body marker';
        }

        return $signals;
    }
}
