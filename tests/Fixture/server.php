<?php

declare(strict_types=1);

/**
 * Fixture server used by the integration tests.
 *
 * Routes:
 *   /            → 200 JSON, sets X-Powered-By: PHP/8.1.29 and Server: Apache/2.4.58 (Unix) PHP/8.1.29
 *   /headers     → 200 with no security headers at all
 *   /secure      → 200 with a full set of security headers
 *   /.env        → 200 with a fake .env body
 *   /missing     → 404 with an Apache-style body and the PHP-bearing Server header
 *   /shell.php   → 200 with a webshell body
 *   /slow        → 200 after a 1 second delay
 *   /redirect    → 302 to the same server under a different host name
 */
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

header_remove('X-Powered-By');
header('Server: Apache/2.4.58 (Unix) PHP/8.1.29');

switch ($path) {
    case '/headers':
        http_response_code(200);
        echo 'plain';
        break;

    case '/secure':
        http_response_code(200);
        header('Content-Security-Policy: default-src \'self\'');
        header('Strict-Transport-Security: max-age=31536000');
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('Referrer-Policy: no-referrer');
        header('X-Permitted-Cross-Domain-Policies: none');
        echo 'secure';
        break;

    case '/.env':
        http_response_code(200);
        echo "APP_KEY=base64:deadbeef\nDB_PASSWORD=hunter2\n";
        break;

    case '/missing':
        http_response_code(404);
        echo '<html><body>Not Found</body></html>';
        break;

    case '/shell.php':
        http_response_code(200);
        echo "<?php system(\$_GET['c']); ?>";
        break;

    case '/slow':
        sleep(1);
        http_response_code(200);
        echo 'slow';
        break;

    case '/redirect':
        // Reached through 127.0.0.1 this leaves the host; reached through
        // localhost it stays on the same host.
        http_response_code(302);
        header(sprintf('Location: http://localhost:%d/secure', (int) ($_SERVER['SERVER_PORT'] ?? 80)));
        break;

    case '/search':
        $q = (string) ($_GET['q'] ?? '');

        // A quote reaches the "database" here, so the SQL check has something
        // real to confirm against. Everything else is reflected and escaped.
        if (str_contains($q, "'")) {
            http_response_code(500);
            echo 'SQL syntax error';

            break;
        }

        echo 'results for ' . htmlspecialchars($q, ENT_QUOTES);
        break;

    default:
        http_response_code(200);
        header('X-Powered-By: PHP/8.1.29');
        header('Content-Type: application/json');
        echo json_encode(['ok' => true]);
        break;
}
