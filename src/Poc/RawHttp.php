<?php

declare(strict_types=1);

namespace Php2ShellTui\Poc;

final class RawHttp
{
    private const READ_CAP = 4 * 1024 * 1024;
    private const CHUNK_SIZE = 65536;

    /**
     * @var list<resource>
     */
    private array $sockets = [];

    /**
     * @param array<string, string> $headers
     */
    public function __construct(
        private readonly string $scheme,
        private readonly string $host,
        private readonly int $port,
        private readonly float $timeout,
        private readonly array $headers = [],
    ) {
        if (!in_array($scheme, ['http', 'https'], true)) {
            throw new \InvalidArgumentException('RawHttp scheme must be "http" or "https".');
        }

        if ($host === '' || $port < 1 || $port > 65535 || $timeout <= 0) {
            throw new \InvalidArgumentException('RawHttp host, port, or timeout is invalid.');
        }
    }

    public function sendChunked(string $path, string $bodyFile, string $boundary = 'CCCCCCCCCC'): string
    {
        if ($path === '' || $path[0] !== '/') {
            throw new \InvalidArgumentException('RawHttp path must start with "/".');
        }

        if ($boundary === '' || str_contains($boundary, "\r") || str_contains($boundary, "\n")) {
            throw new \InvalidArgumentException('RawHttp boundary is invalid.');
        }

        $body = @fopen($bodyFile, 'rb');
        if ($body === false) {
            throw new \RuntimeException(sprintf('Cannot read the raw body file "%s".', $bodyFile));
        }

        $socket = null;

        try {
            $socket = $this->connect();
            $this->writeAll($socket, $this->requestHead(
                method: 'POST',
                path: $path,
                contentType: 'multipart/form-data; boundary=' . $boundary,
                contentLength: null,
                connection: 'close',
            ));

            while (!feof($body)) {
                $chunk = fread($body, self::CHUNK_SIZE);
                if ($chunk === false) {
                    throw new \RuntimeException('Cannot read the raw body file.');
                }

                if ($chunk === '') {
                    continue;
                }

                $this->writeAll($socket, dechex(strlen($chunk)) . "\r\n" . $chunk . "\r\n");
            }

            $this->writeAll($socket, "0\r\n\r\n");

            return $this->readResponse($socket);
        } finally {
            if (is_resource($body)) {
                fclose($body);
            }

            if (is_resource($socket)) {
                fclose($socket);
            }
        }
    }

    public function sendBody(string $path, string $bodyFile, string $contentType): string
    {
        if ($path === '' || $path[0] !== '/') {
            throw new \InvalidArgumentException('RawHttp path must start with "/".');
        }

        if ($contentType === '' || str_contains($contentType, "\r") || str_contains($contentType, "\n")) {
            throw new \InvalidArgumentException('RawHttp content type is invalid.');
        }

        $length = @filesize($bodyFile);
        if ($length === false) {
            throw new \RuntimeException(sprintf('Cannot read the raw body file "%s".', $bodyFile));
        }

        $body = @fopen($bodyFile, 'rb');
        if ($body === false) {
            throw new \RuntimeException(sprintf('Cannot read the raw body file "%s".', $bodyFile));
        }

        $socket = null;

        try {
            $socket = $this->connect();
            $this->writeAll($socket, $this->requestHead(
                method: 'POST',
                path: $path,
                contentType: $contentType,
                contentLength: $length,
                connection: 'close',
            ));

            while (!feof($body)) {
                $chunk = fread($body, self::CHUNK_SIZE);
                if ($chunk === false) {
                    throw new \RuntimeException('Cannot read the raw body file.');
                }

                if ($chunk !== '') {
                    $this->writeAll($socket, $chunk);
                }
            }

            return $this->readResponse($socket);
        } finally {
            if (is_resource($body)) {
                fclose($body);
            }

            if (is_resource($socket)) {
                fclose($socket);
            }
        }
    }

    /**
     * @return resource
     */
    public function openIncompletePost(string $path, int $contentLength): mixed
    {
        if ($path === '' || $path[0] !== '/') {
            throw new \InvalidArgumentException('RawHttp path must start with "/".');
        }

        if ($contentLength < 1) {
            throw new \InvalidArgumentException('RawHttp content length must be positive.');
        }

        $socket = $this->connect();

        try {
            $this->writeAll($socket, $this->requestHead(
                method: 'POST',
                path: $path,
                contentType: 'application/x-www-form-urlencoded',
                contentLength: $contentLength,
                connection: 'keep-alive',
            ) . 'x');
        } catch (\Throwable $e) {
            fclose($socket);

            throw $e;
        }

        $this->sockets[] = $socket;

        return $socket;
    }

    public function close(): void
    {
        foreach ($this->sockets as $socket) {
            if (is_resource($socket)) {
                fclose($socket);
            }
        }

        $this->sockets = [];
    }

    public function __destruct()
    {
        $this->close();
    }

    /**
     * @return resource
     */
    private function connect(): mixed
    {
        $host = $this->host;
        if (str_contains($host, ':') && !str_starts_with($host, '[')) {
            $host = '[' . $host . ']';
        }

        $remote = sprintf('%s://%s:%d', $this->scheme === 'https' ? 'tls' : 'tcp', $host, $this->port);
        $context = stream_context_create($this->scheme === 'https' ? [
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
                'SNI_enabled' => true,
                'peer_name' => $this->host,
            ],
        ] : []);

        $socket = @stream_socket_client(
            $remote,
            $errno,
            $errstr,
            $this->timeout,
            STREAM_CLIENT_CONNECT,
            $context,
        );

        if ($socket === false) {
            throw new \RuntimeException(sprintf('Cannot connect to %s: %s', $remote, $errstr !== '' ? $errstr : 'unknown error'));
        }

        $seconds = (int) floor($this->timeout);
        $micros = (int) (($this->timeout - $seconds) * 1_000_000);
        stream_set_timeout($socket, $seconds, $micros);

        return $socket;
    }

    private function requestHead(
        string $method,
        string $path,
        string $contentType,
        ?int $contentLength,
        string $connection,
    ): string {
        $host = $this->hostHeader();
        $extra = [];

        foreach ($this->headers as $name => $value) {
            $lower = strtolower($name);

            if ($lower === 'host') {
                $host = $value;
                continue;
            }

            if (in_array($lower, ['content-type', 'content-length', 'transfer-encoding', 'connection', 'expect'], true)) {
                continue;
            }

            $extra[] = $name . ': ' . $value;
        }

        $lines = [
            sprintf('%s %s HTTP/1.1', $method, $path),
            'Host: ' . $host,
            'Content-Type: ' . $contentType,
        ];

        if ($contentLength !== null) {
            $lines[] = 'Content-Length: ' . $contentLength;
        } else {
            $lines[] = 'Transfer-Encoding: chunked';
        }

        $lines[] = 'Connection: ' . $connection;

        foreach ($extra as $line) {
            $lines[] = $line;
        }

        return implode("\r\n", $lines) . "\r\n\r\n";
    }

    private function hostHeader(): string
    {
        $host = $this->host;

        if (str_contains($host, ':') && !str_starts_with($host, '[')) {
            $host = '[' . $host . ']';
        }

        return $host . ':' . $this->port;
    }

    /**
     * @param resource $socket
     */
    private function writeAll(mixed $socket, string $data): void
    {
        $length = strlen($data);
        $offset = 0;

        while ($offset < $length) {
            $written = fwrite($socket, substr($data, $offset));

            if ($written === false || $written === 0) {
                throw new \RuntimeException('Cannot write to the raw socket.');
            }

            $offset += $written;
        }
    }

    /**
     * @param resource $socket
     */
    private function readResponse(mixed $socket): string
    {
        $response = '';
        $headerEnd = null;
        $searchFrom = 0;
        $contentLength = null;
        $chunked = false;

        while (strlen($response) < self::READ_CAP) {
            $chunk = fread($socket, 65536);

            if ($chunk === false) {
                break;
            }

            if ($chunk === '') {
                $meta = stream_get_meta_data($socket);

                if (($meta['timed_out'] ?? false) === true || feof($socket)) {
                    break;
                }

                usleep(1_000);
                continue;
            }

            $response .= $chunk;

            while ($headerEnd === null) {
                $position = strpos($response, "\r\n\r\n", $searchFrom);

                if ($position === false) {
                    break;
                }

                $block = substr($response, $searchFrom, $position - $searchFrom);
                $status = strtok($block, "\r\n") ?: '';

                if (preg_match('#^HTTP/\d(?:\.\d)?\s+1\d\d\b#i', $status) === 1) {
                    $searchFrom = $position + 4;
                    continue;
                }

                $headerEnd = $position + 4;

                if (preg_match('/^Content-Length:\s*(\d+)/mi', $block, $matches) === 1) {
                    $contentLength = (int) $matches[1];
                }

                if (preg_match('/^Transfer-Encoding:\s*chunked/mi', $block) === 1) {
                    $chunked = true;
                }
            }

            if ($headerEnd !== null) {
                if ($contentLength !== null && strlen($response) >= $headerEnd + $contentLength) {
                    break;
                }

                if ($chunked && str_contains(substr($response, $headerEnd), "\r\n0\r\n\r\n")) {
                    break;
                }
            }
        }

        return $response;
    }
}
