<?php

declare(strict_types=1);

/**
 * Minimal raw HTTP server for RawHttp tests.
 *
 * argv: port, capture path, ready path, mode (chunked|incomplete)
 */
$port = (int) ($argv[1] ?? 0);
$capture = (string) ($argv[2] ?? '');
$ready = (string) ($argv[3] ?? '');
$mode = (string) ($argv[4] ?? 'chunked');

$server = @stream_socket_server('tcp://127.0.0.1:' . $port, $errno, $errstr);

if ($server === false) {
    fwrite(STDERR, sprintf("raw_server: %s\n", $errstr));
    exit(1);
}

file_put_contents($ready, 'ready');
$client = @stream_socket_accept($server, 10.0);

if ($client === false) {
    fclose($server);
    exit(2);
}

stream_set_timeout($client, 5);
$data = '';

if ($mode === 'early') {
    while (!str_contains($data, "\r\n\r\n")) {
        $chunk = fread($client, 8192);
        if ($chunk === false || $chunk === '') {
            break;
        }
        $data .= $chunk;
    }

    file_put_contents($capture, $data);
    fwrite($client, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nEARLY");
    fclose($client);
    fclose($server);
    exit;
}

if ($mode === 'interim') {
    while (!str_contains($data, "\r\n\r\n")) {
        $chunk = fread($client, 8192);
        if ($chunk === false || $chunk === '') {
            break;
        }
        $data .= $chunk;
    }

    file_put_contents($capture, $data);
    fwrite($client, "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK");
    fclose($client);
    fclose($server);
    exit;
}

if ($mode === 'body') {
    while (!str_contains($data, "\r\n\r\n")) {
        $chunk = fread($client, 8192);
        if ($chunk === false || $chunk === '') {
            break;
        }
        $data .= $chunk;
    }

    $headerEnd = strpos($data, "\r\n\r\n");
    $headers = $headerEnd === false ? '' : substr($data, 0, $headerEnd);
    preg_match('/^Content-Length:\s*(\d+)/mi', $headers, $matches);
    $length = (int) ($matches[1] ?? 0);
    $body = $headerEnd === false ? '' : substr($data, $headerEnd + 4);

    while (strlen($body) < $length) {
        $chunk = fread($client, 8192);
        if ($chunk === false || $chunk === '') {
            break;
        }
        $body .= $chunk;
    }

    $captured = $headerEnd === false ? $data : substr($data, 0, $headerEnd + 4) . $body;
    file_put_contents($capture, $captured);
    fwrite($client, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK");
} elseif ($mode === 'incomplete') {
    while (!str_contains($data, "\r\n\r\n")) {
        $chunk = fread($client, 8192);
        if ($chunk === false || $chunk === '') {
            break;
        }
        $data .= $chunk;
    }

    $headerEnd = strpos($data, "\r\n\r\n");
    if ($headerEnd !== false && substr($data, $headerEnd + 4) === '') {
        $data .= (string) fread($client, 1);
    }

    file_put_contents($capture, $data);
    usleep(200_000);
} else {
    $deadline = microtime(true) + 5.0;

    while (microtime(true) < $deadline) {
        $chunk = fread($client, 8192);
        if ($chunk === false) {
            break;
        }

        if ($chunk === '') {
            $meta = stream_get_meta_data($client);
            if (($meta['timed_out'] ?? false) === true || feof($client)) {
                break;
            }
            usleep(1_000);
            continue;
        }

        $data .= $chunk;
        if (str_contains($data, "\r\n0\r\n\r\n")) {
            break;
        }
    }

    file_put_contents($capture, $data);
    fwrite($client, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK");
}

fclose($client);
fclose($server);
