<?php

declare(strict_types=1);

namespace Php2ShellTui\Check;

use Php2ShellTui\Data\Reproduce;
use Php2ShellTui\Data\Wordlists;
use Php2ShellTui\Finding;
use Php2ShellTui\Http\Client;
use Php2ShellTui\Severity;
use Php2ShellTui\Target;
use Psr\Http\Message\ResponseInterface;

final class OpenPorts implements Check
{
    private const HIGH_PORTS = [3306, 5432, 6379, 27017, 9200];

    private const WEB_PORTS = [80, 443];

    /**
     * @param null|\Closure(string, int): ?string $prober returns evidence for an
     *        open service, or null when the port is closed or only a CDN edge
     */
    public function __construct(
        private readonly Wordlists $wordlists,
        private readonly Reproduce $reproduce,
        private readonly ?\Closure $prober = null,
        private readonly ?Client $client = null,
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

            $evidence = $this->prober !== null
                ? ($this->prober)($host, $port)
                : $this->probe($host, $port);

            if ($evidence === null) {
                continue;
            }

            $findings[] = new Finding(
                id: 'open-port-' . $port,
                title: sprintf('Port %d is open', $port),
                severity: in_array($port, self::HIGH_PORTS, true) ? Severity::High : Severity::Medium,
                target: $target->label(),
                evidence: sprintf('Port %d answered on %s: %s.', $port, $host, $evidence),
                exploit: sprintf('Connect to %s:%d directly - the service is reachable from outside and may not require authentication.', $host, $port),
                reproduce: $this->reproduce->steps('open-ports', $target->url, $target->label()),
            );
        }

        return $findings;
    }

    private function probe(string $host, int $port): ?string
    {
        // ponytail: ports are probed sequentially at 150ms each. Fine for the
        // curated list; pool them through the HTTP handler if scan time matters.
        $errno = 0;
        $errstr = '';
        $socket = @stream_socket_client(
            sprintf('tcp://%s:%d', $host, $port),
            $errno,
            $errstr,
            0.15
        );

        if ($socket === false) {
            return null;
        }

        fclose($socket);

        if (!in_array($port, [8080, 8443], true) || $this->client === null) {
            return 'TCP connection accepted';
        }

        // Cloudflare accepts connections on its alternate web ports for every
        // proxied hostname. The HTTP response proves whether a real service or
        // only the shared CDN edge answered.
        try {
            $response = $this->client->guzzle()->request('GET', sprintf('http://%s:%d/', $host, $port), [
                'http_errors' => false,
                'allow_redirects' => false,
                'timeout' => 1,
                'connect_timeout' => 0.5,
                'headers' => ['Connection' => 'close'],
            ]);
        } catch (\Throwable) {
            // The TCP connection was open, but the service did not answer HTTP.
            return 'TCP connection accepted';
        }

        return self::evidenceFromResponse($response);
    }

    /**
     * A Cloudflare response belongs to the shared edge, not to the scanned
     * origin, even when the TCP port is open.
     */
    public static function evidenceFromResponse(ResponseInterface $response): ?string
    {
        $server = trim($response->getHeaderLine('Server'));

        if (stripos($server, 'cloudflare') !== false
            || $response->hasHeader('CF-RAY')
            || $response->hasHeader('CF-Cache-Status')) {
            return null;
        }

        $status = $response->getStatusCode();

        return $server === ''
            ? sprintf('HTTP %d', $status)
            : sprintf('HTTP %d (Server: %s)', $status, $server);
    }
}
