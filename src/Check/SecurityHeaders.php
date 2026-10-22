<?php

declare(strict_types=1);

namespace Php2Scan\Check;

use Aidantwoods\SecureHeaders\HeaderBag;
use Aidantwoods\SecureHeaders\Validator;
use Php2Scan\Data\Reproduce;
use Php2Scan\Finding;
use Php2Scan\Severity;
use Php2Scan\Target;
use Psr\Http\Message\ResponseInterface;

final class SecurityHeaders implements Check
{
    private const HEADERS = [
        'Content-Security-Policy' => Severity::Low,
        'X-Content-Type-Options' => Severity::Medium,
        'Referrer-Policy' => Severity::Low,
        'X-Permitted-Cross-Domain-Policies' => Severity::Low,
    ];

    public function __construct(private readonly Reproduce $reproduce)
    {
    }

    public function id(): string
    {
        return 'security_headers';
    }

    public function paths(Target $target, ?ResponseInterface $baseline): array
    {
        return ['/'];
    }

    public function analyze(Target $target, array $responses): array
    {
        $response = $responses['/'] ?? null;
        if ($response === null) {
            return [];
        }

        $findings = [];
        $isHttps = str_starts_with($target->url, 'https://');

        foreach (self::HEADERS as $header => $severity) {
            if ($response->hasHeader($header)) {
                continue;
            }

            $findings[] = $this->finding(
                'missing-header-' . strtolower($header),
                sprintf('Missing %s header', $header),
                $severity,
                $target,
                sprintf('The response has no %s header.', $header),
                'Send a request without that header and observe the browser has no protection - the header can be added at the edge or in the application.',
            );
        }

        if ($isHttps && !$response->hasHeader('Strict-Transport-Security')) {
            $findings[] = $this->finding(
                'missing-header-strict-transport-security',
                'Missing Strict-Transport-Security header',
                Severity::Medium,
                $target,
                'The HTTPS response has no Strict-Transport-Security header.',
                'Request the site over plain HTTP and follow the redirect - without HSTS the browser can be downgraded to cleartext.',
            );
        }

        if (!$response->hasHeader('X-Frame-Options') && !$this->hasFrameAncestors($response)) {
            $findings[] = $this->finding(
                'missing-header-x-frame-options',
                'Missing X-Frame-Options header',
                Severity::Medium,
                $target,
                'The response has neither X-Frame-Options nor a CSP frame-ancestors directive.',
                'Embed the target in an iframe on a page you control - without frame protection the clickjacking overlay succeeds.',
            );
        }

        foreach ($response->getHeader('Set-Cookie') as $cookie) {
            $name = self::cookieName($cookie);
            $missing = [];

            if (stripos($cookie, 'secure') === false) {
                $missing[] = 'Secure';
            }
            if (stripos($cookie, 'httponly') === false) {
                $missing[] = 'HttpOnly';
            }
            if (stripos($cookie, 'samesite') === false) {
                $missing[] = 'SameSite';
            }

            if ($missing === []) {
                continue;
            }

            $findings[] = $this->finding(
                'cookie-flags-' . strtolower($name),
                sprintf('Cookie "%s" is missing %s', $name, implode(', ', $missing)),
                Severity::Medium,
                $target,
                sprintf('Set-Cookie: %s', $cookie),
                sprintf('Replay the session cookie from a script or a plain-HTTP request - the missing %s flag lets it leave the browser or be read by JavaScript.', implode(' and ', $missing)),
            );
        }

        foreach ($this->validateValues($response) as $problem) {
            $findings[] = $this->finding(
                'insecure-csp',
                'Weak Content-Security-Policy',
                Severity::Medium,
                $target,
                $problem,
                'Load the page and inject a script - the policy permits it, so the injection executes in the page origin.',
            );
        }

        return $findings;
    }

    private function hasFrameAncestors(ResponseInterface $response): bool
    {
        $csp = $response->getHeaderLine('Content-Security-Policy');

        return $csp !== '' && stripos($csp, 'frame-ancestors') !== false;
    }

    /**
     * @return list<string>
     */
    private function validateValues(ResponseInterface $response): array
    {
        $headers = [];
        foreach ($response->getHeaders() as $name => $values) {
            $headers[$name] = implode(', ', $values);
        }

        $problems = [];

        try {
            $errors = Validator::validate(new HeaderBag($headers));
        } catch (\Throwable) {
            return [];
        }

        foreach ($errors as $error) {
            $problems[] = trim(strip_tags($error->getMessage()));
        }

        return $problems;
    }

    private static function cookieName(string $cookie): string
    {
        $parts = explode('=', $cookie, 2);

        return trim($parts[0]);
    }

    private function finding(
        string $id,
        string $title,
        Severity $severity,
        Target $target,
        string $evidence,
        string $exploit,
    ): Finding {
        return new Finding(
            id: $id,
            title: $title,
            severity: $severity,
            target: $target->label(),
            evidence: $evidence,
            exploit: $exploit,
            reproduce: $this->reproduce->steps('security-headers', $target->url, $target->label()),
        );
    }
}
