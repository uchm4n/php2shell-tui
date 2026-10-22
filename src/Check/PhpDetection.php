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
                title: 'No PHP detected',
                severity: Severity::Info,
                target: $target->label(),
                evidence: 'No X-Powered-By header, no PHP in the Server header, no PHP session cookie.',
                exploit: 'Nothing to exploit here - this host does not serve PHP, so PHP2Shell cannot apply.',
                reproduce: $this->reproduce->steps('php_presence', $target->url, $target->label()),
            )];
        }

        return [new Finding(
            id: 'php_presence',
            title: 'PHP detected',
            severity: Severity::Info,
            target: $target->label(),
            evidence: 'Signals: ' . implode(', ', $signals) . '.',
            exploit: 'Confirm the runtime version on the host with "php -v" - every PHP release before 8.2.35 is exposed to PHP2Shell.',
            reproduce: $this->reproduce->steps('php_presence', $target->url, $target->label()),
        )];
    }

    /**
     * @return list<string>
     */
    public static function signals(ResponseInterface $response): array
    {
        $signals = [];

        $poweredBy = $response->getHeaderLine('X-Powered-By');
        if ($poweredBy !== '') {
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

        $body = (string) $response->getBody();
        if ($body !== '' && preg_match('/Powered by PHP|<meta[^>]+generator[^>]+PHP/i', $body) === 1) {
            $signals[] = 'body marker';
        }

        return $signals;
    }
}
