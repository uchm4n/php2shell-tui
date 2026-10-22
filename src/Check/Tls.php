<?php

declare(strict_types=1);

namespace Php2Scan\Check;

use Php2Scan\Data\Reproduce;
use Php2Scan\Finding;
use Php2Scan\Severity;
use Php2Scan\Target;
use Psr\Http\Message\ResponseInterface;

final class Tls implements Check
{
    /**
     * A certificate that expires within this many days is reported.
     */
    private const EXPIRING_WITHIN_DAYS = 14;

    /**
     * @param null|\Closure(string, int): (array<string, mixed>|null) $certificateResolver
     */
    public function __construct(
        private readonly Reproduce $reproduce,
        private readonly ?\Closure $certificateResolver = null,
    ) {
    }

    public function id(): string
    {
        return 'tls';
    }

    public function paths(Target $target, ?ResponseInterface $baseline): array
    {
        return [];
    }

    public function analyze(Target $target, array $responses): array
    {
        if (!str_starts_with($target->url, 'https://')) {
            return [];
        }

        $host = $target->host();
        $port = (int) (parse_url($target->url, PHP_URL_PORT) ?: 443);

        $certificate = $this->certificateResolver !== null
            ? ($this->certificateResolver)($host, $port)
            : self::fetchCertificate($host, $port);

        if ($certificate === null) {
            return [];
        }

        $steps = $this->reproduce->steps('tls', $target->url, $target->label());
        $findings = [];

        $validTo = (int) ($certificate['validTo'] ?? 0);

        if ($validTo > 0) {
            $days = (int) floor(($validTo - time()) / 86400);

            if ($days < 0) {
                $findings[] = new Finding(
                    id: 'tls-expired',
                    title: 'Expired TLS certificate',
                    severity: Severity::Critical,
                    target: $target->label(),
                    evidence: sprintf('The certificate expired %d days ago (%s).', abs($days), gmdate('Y-m-d', $validTo)),
                    exploit: 'Request the site and watch the browser block it - the expired certificate also breaks any client that validates certificates, such as curl without -k.',
                    reproduce: $steps,
                );
            } elseif ($days <= self::EXPIRING_WITHIN_DAYS) {
                $findings[] = new Finding(
                    id: 'tls-expiring',
                    title: 'TLS certificate expires soon',
                    severity: Severity::Medium,
                    target: $target->label(),
                    evidence: sprintf('The certificate expires in %d days (%s).', $days, gmdate('Y-m-d', $validTo)),
                    exploit: 'Wait for the expiry, or force an outage by presenting a certificate the client does not trust - the renewal failure becomes a full outage.',
                    reproduce: $steps,
                );
            }
        }

        if (!self::coversHost($certificate, $host)) {
            $findings[] = new Finding(
                id: 'tls-hostname-mismatch',
                title: 'TLS certificate does not cover the hostname',
                severity: Severity::Medium,
                target: $target->label(),
                evidence: sprintf(
                    'The certificate is issued for "%s" but the host is "%s".',
                    implode(', ', self::names($certificate)),
                    $host,
                ),
                exploit: 'A client that validates the certificate name refuses the site, and a client that does not validate it can be intercepted - the certificate belongs to a different host.',
                reproduce: $steps,
            );
        }

        return $findings;
    }

    /**
     * Does the certificate claim the host it was served on?
     *
     * @param array<string, mixed> $certificate
     */
    private static function coversHost(array $certificate, string $host): bool
    {
        $names = self::names($certificate);

        if ($names === []) {
            // The certificate names nothing, so there is nothing to compare
            // against - report nothing rather than guess.
            return true;
        }

        foreach ($names as $name) {
            if (self::matches($name, $host)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The names the certificate is issued for: the common name and the
     * subject alternative names.
     *
     * @param array<string, mixed> $certificate
     * @return list<string>
     */
    private static function names(array $certificate): array
    {
        $names = [];

        $subject = (string) ($certificate['subject'] ?? '');
        // OpenSSL prints the subject in its oneline form ("/CN=host/O=Org");
        // the plain "CN=host" form is accepted as well.
        if (preg_match('~(?:^|[/,\s])CN=([^,/]+)~i', $subject, $matches) === 1) {
            $names[] = trim($matches[1]);
        }

        $san = $certificate['san'] ?? [];
        if (is_string($san)) {
            $san = explode(',', $san);
        }

        foreach ((array) $san as $name) {
            $names[] = trim((string) $name);
        }

        return array_values(array_filter(array_map('strtolower', $names)));
    }

    /**
     * A wildcard covers one label only: *.example.com covers a.example.com
     * but not example.com.
     */
    private static function matches(string $name, string $host): bool
    {
        if ($name === $host) {
            return true;
        }

        if (!str_starts_with($name, '*.')) {
            return false;
        }

        $suffix = substr($name, 1);

        return str_ends_with($host, $suffix) && $host !== ltrim($suffix, '.');
    }

    /**
     * @return array<string, mixed>|null
     */
    private static function fetchCertificate(string $host, int $port): ?array
    {
        $context = stream_context_create([
            'ssl' => [
                // The certificate is examined even when it is expired, self-signed
                // or issued for another name - those are exactly the findings this
                // check reports, so peer verification must stay off here.
                'capture_peer_cert' => true,
                'verify_peer' => false,
                'verify_peer_name' => false,
            ],
        ]);

        $errno = 0;
        $errstr = '';
        $socket = @stream_socket_client(
            sprintf('ssl://%s:%d', $host, $port),
            $errno,
            $errstr,
            5,
            STREAM_CLIENT_CONNECT,
            $context
        );

        if ($socket === false) {
            return null;
        }

        $options = stream_context_get_options($socket);
        $peer = $options['ssl']['peer_certificate'] ?? null;
        fclose($socket);

        if ($peer === null) {
            return null;
        }

        $parsed = @openssl_x509_parse($peer);
        if ($parsed === false) {
            return null;
        }

        return [
            'validFrom' => (int) ($parsed['validFrom_time_t'] ?? 0),
            'validTo' => (int) ($parsed['validTo_time_t'] ?? 0),
            'subject' => (string) ($parsed['name'] ?? ''),
            'san' => self::alternativeNames((string) ($parsed['extensions']['subjectAltName'] ?? '')),
        ];
    }

    /**
     * @return list<string>
     */
    private static function alternativeNames(string $subjectAltName): array
    {
        $names = [];

        foreach (explode(',', $subjectAltName) as $entry) {
            $entry = trim($entry);

            if (str_starts_with($entry, 'DNS:')) {
                $names[] = strtolower(substr($entry, 4));
            }
        }

        return $names;
    }
}
