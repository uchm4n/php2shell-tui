<?php

declare(strict_types=1);

namespace Php2ShellTui\Poc;

final class RawHttp
{
    private const WRITE_CHUNK = 262144;
    private const READ_CHUNK = 65536;

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

    /**
     * @param array<string, string> $extraHeaders
     */
    public function sendBody(
        string $path,
        string $bodyFile,
        string $contentType,
        int $readCap,
        ?float $timeout = null,
        array $extraHeaders = [],
    ): string {
        $this->validatePath($path);
        $this->validateContentType($contentType);

        $body = @fopen($bodyFile, 'rb');
        if ($body === false) {
            throw new \RuntimeException(sprintf('Cannot read the raw body file "%s".', $bodyFile));
        }

        $size = @filesize($bodyFile);
        if ($size === false) {
            fclose($body);
            throw new \RuntimeException(sprintf('Cannot read the raw body file "%s".', $bodyFile));
        }

        try {
            return $this->exchange(
                $this->requestHead('POST', $path, $contentType, $size, 'close', $extraHeaders),
                $body,
                $size,
                $readCap,
                $timeout ?? $this->timeout,
            );
        } finally {
            fclose($body);
        }
    }

    /**
     * @param array<string, string> $extraHeaders
     */
    public function sendNow(
        string $path,
        string $bodyFile,
        string $contentType,
        ?float $timeout = null,
        array $extraHeaders = [],
    ): void {
        $this->validatePath($path);
        $this->validateContentType($contentType);

        $body = @fopen($bodyFile, 'rb');
        if ($body === false) {
            throw new \RuntimeException(sprintf('Cannot read the raw body file "%s".', $bodyFile));
        }

        $size = @filesize($bodyFile);
        if ($size === false) {
            fclose($body);
            throw new \RuntimeException(sprintf('Cannot read the raw body file "%s".', $bodyFile));
        }

        try {
            $this->exchange(
                $this->requestHead('POST', $path, $contentType, $size, 'close', $extraHeaders),
                $body,
                $size,
                4096,
                $timeout ?? $this->timeout,
                0.2,
            );
        } finally {
            fclose($body);
        }
    }

    /**
     * @return resource
     */
    public function openIncompletePost(string $path, int $contentLength): mixed
    {
        $this->validatePath($path);

        if ($contentLength < 1) {
            throw new \InvalidArgumentException('RawHttp content length must be positive.');
        }

        $socket = $this->connect();

        try {
            $this->writeAll($socket, $this->requestHead(
                'POST',
                $path,
                'application/x-www-form-urlencoded',
                $contentLength,
                'keep-alive',
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
     * @param resource $body
     * @return string
     */
    private function exchange(
        string $head,
        mixed $body,
        int $bodySize,
        int $readCap,
        float $timeout,
        ?float $linger = null,
    ): string {
        if ($readCap < 1) {
            throw new \InvalidArgumentException('RawHttp read cap must be positive.');
        }

        $socket = $this->connect();
        stream_set_blocking($socket, false);
        $deadline = microtime(true) + $timeout;
        $readDeadline = null;
        $headOffset = 0;
        $remaining = $bodySize;
        $pending = '';
        $response = '';
        $writeFailed = false;

        try {
            while (microtime(true) < $deadline) {
                if ($readDeadline !== null && microtime(true) >= $readDeadline) {
                    break;
                }

                $read = [$socket];
                $write = $socket !== null && !$writeFailed && ($pending !== '' || $headOffset < strlen($head) || $remaining > 0)
                    ? [$socket]
                    : [];
                $except = null;
                $ready = @stream_select($read, $write, $except, 0, 200000);

                if ($ready === false) {
                    break;
                }

                if ($write !== []) {
                    if ($pending === '') {
                        if ($headOffset < strlen($head)) {
                            $pending = substr($head, $headOffset, self::WRITE_CHUNK);
                            $headOffset += strlen($pending);
                        } elseif ($remaining > 0) {
                            $chunk = fread($body, min(self::WRITE_CHUNK, $remaining));
                            if ($chunk === false) {
                                $writeFailed = true;
                                $remaining = 0;
                            } elseif ($chunk === '') {
                                if (feof($body)) {
                                    $writeFailed = true;
                                    $remaining = 0;
                                }
                            } else {
                                $pending = $chunk;
                                $remaining -= strlen($chunk);
                            }
                        }
                    }

                    if ($pending !== '') {
                        $written = @fwrite($socket, $pending);
                        if ($written === false || $written === 0) {
                            $writeFailed = true;
                            $pending = '';
                            $remaining = 0;
                        } else {
                            $pending = substr($pending, $written);
                        }
                    }

                    if ($readDeadline === null && $headOffset >= strlen($head) && $remaining <= 0 && $pending === '') {
                        $readDeadline = $linger === null ? null : microtime(true) + $linger;
                    }
                }

                if ($read !== []) {
                    $chunk = @fread($socket, self::READ_CHUNK);
                    if ($chunk === false) {
                        break;
                    }

                    if ($chunk === '') {
                        if (feof($socket)) {
                            break;
                        }
                    } else {
                        $response .= $chunk;
                        if (strlen($response) >= $readCap) {
                            break;
                        }
                        if (self::responseComplete($response)) {
                            break;
                        }
                    }
                }

                if ($readDeadline === null && $headOffset >= strlen($head) && $remaining <= 0 && $pending === '' && $linger !== null) {
                    $readDeadline = microtime(true) + $linger;
                }
            }
        } finally {
            fclose($socket);
        }

        return $response;
    }

    private static function responseComplete(string $response): bool
    {
        $headerEnd = strpos($response, "\r\n\r\n");
        if ($headerEnd === false) {
            return false;
        }

        $headers = substr($response, 0, $headerEnd);

        if (preg_match('/^HTTP\/\d(?:\.\d)?\s+1\d\d\b/', $headers) === 1
            && preg_match('/^HTTP\/\d(?:\.\d)?\s+2\d\d\b/m', $headers) !== 1) {
            return false;
        }

        if (preg_match('/^Content-Length:\s*(\d+)/mi', $headers, $matches) === 1) {
            return strlen($response) >= $headerEnd + 4 + (int) $matches[1];
        }

        if (preg_match('/^Transfer-Encoding:\s*chunked/mi', $headers) === 1) {
            return str_contains(substr($response, $headerEnd + 4), "\r\n0\r\n\r\n");
        }

        return false;
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

    /**
     * @param array<string, string> $extraHeaders
     */
    private function requestHead(
        string $method,
        string $path,
        string $contentType,
        ?int $contentLength,
        string $connection,
        array $extraHeaders = [],
    ): string {
        $host = $this->hostHeader();
        $extra = [];

        foreach (array_merge($this->headers, $extraHeaders) as $name => $value) {
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
        }

        $lines[] = 'Connection: ' . $connection;
        $lines = array_merge($lines, $extra);

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

    private function validatePath(string $path): void
    {
        if ($path === '' || $path[0] !== '/') {
            throw new \InvalidArgumentException('RawHttp path must start with "/".');
        }
    }

    private function validateContentType(string $contentType): void
    {
        if ($contentType === '' || str_contains($contentType, "\r") || str_contains($contentType, "\n")) {
            throw new \InvalidArgumentException('RawHttp content type is invalid.');
        }
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
}
