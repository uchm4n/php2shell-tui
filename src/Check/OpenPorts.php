<?php

declare(strict_types=1);

namespace Php2Scan\Check;

use Php2Scan\Data\Reproduce;
use Php2Scan\Data\Wordlists;
use Php2Scan\Finding;
use Php2Scan\Severity;
use Php2Scan\Target;
use Psr\Http\Message\ResponseInterface;

final class OpenPorts implements Check
{
    private const HIGH_PORTS = [3306, 5432, 6379, 27017, 9200];

    private const WEB_PORTS = [80, 443];

    /**
     * @param null|\Closure(string, int): bool $prober
     */
    public function __construct(
        private readonly Wordlists $wordlists,
        private readonly Reproduce $reproduce,
        private readonly ?\Closure $prober = null,
    ) {
    }

    public function id(): string
    {
        return 'open_ports';
    }

    public function paths(Target $target, ?ResponseInterface $baseline): array
    {
        return [];
    }

    public function analyze(Target $target, array $responses): array
    {
        $host = $target->host();
        $findings = [];

        foreach ($this->wordlists->openPorts() as $port) {
            if (in_array($port, self::WEB_PORTS, true)) {
                continue;
            }

            $open = $this->prober !== null
                ? ($this->prober)($host, $port)
                : self::probe($host, $port);

            if (!$open) {
                continue;
            }

            $findings[] = new Finding(
                id: 'open-port-' . $port,
                title: sprintf('Port %d is open', $port),
                severity: in_array($port, self::HIGH_PORTS, true) ? Severity::High : Severity::Medium,
                target: $target->label(),
                evidence: sprintf('TCP port %d accepted a connection on %s.', $port, $host),
                exploit: sprintf('Connect to %s:%d directly - the service is reachable from outside and may not require authentication.', $host, $port),
                reproduce: $this->reproduce->steps('open-ports', $target->url, $target->label()),
            );
        }

        return $findings;
    }

    private static function probe(string $host, int $port): bool
    {
        $errno = 0;
        $errstr = '';
        $socket = @fsockopen($host, $port, $errno, $errstr, 0.15);

        if ($socket === false) {
            return false;
        }

        fclose($socket);

        return true;
    }
}
