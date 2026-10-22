<?php

declare(strict_types=1);

namespace Php2ShellTui\Tests\Unit;

use GuzzleHttp\Psr7\Response;
use Php2ShellTui\Check\SecurityHeaders;
use Php2ShellTui\Data\Reproduce;
use Php2ShellTui\Severity;
use Php2ShellTui\Target;
use PHPUnit\Framework\TestCase;

final class SecurityHeadersTest extends TestCase
{
    private SecurityHeaders $check;

    protected function setUp(): void
    {
        $this->check = new SecurityHeaders(new Reproduce(__DIR__ . '/../../src/Data/repro'));
    }

    public function testAMissingHeaderIsReported(): void
    {
        $findings = $this->check->analyze(new Target('https://example.com'), [
            '/' => new Response(200, [], 'body'),
        ]);

        $ids = array_map(static fn ($f): string => $f->id, $findings);
        self::assertContains('missing-header-x-content-type-options', $ids);
    }

    public function testAFullyHardenedResponseProducesNoHeaderFindings(): void
    {
        $findings = $this->check->analyze(new Target('https://example.com'), [
            '/' => new Response(200, [
                'Content-Security-Policy' => "default-src 'self'",
                'Strict-Transport-Security' => 'max-age=31536000',
                'X-Content-Type-Options' => 'nosniff',
                'X-Frame-Options' => 'DENY',
                'Referrer-Policy' => 'no-referrer',
                'X-Permitted-Cross-Domain-Policies' => 'none',
            ], 'body'),
        ]);

        self::assertSame([], $findings);
    }

    public function testACookieMissingFlagsIsReported(): void
    {
        $findings = $this->check->analyze(new Target('https://example.com'), [
            '/' => new Response(200, ['Set-Cookie' => 'session=abc; path=/'], 'body'),
        ]);

        $ids = array_map(static fn ($f): string => $f->id, $findings);
        self::assertContains('cookie-flags-session', $ids);
    }

    public function testAnInsecureCspIsReported(): void
    {
        $findings = $this->check->analyze(new Target('https://example.com'), [
            '/' => new Response(200, [
                'Content-Security-Policy' => "default-src 'self' 'unsafe-inline' 'none'",
                'Strict-Transport-Security' => 'max-age=31536000',
                'X-Content-Type-Options' => 'nosniff',
                'X-Frame-Options' => 'DENY',
                'Referrer-Policy' => 'no-referrer',
                'X-Permitted-Cross-Domain-Policies' => 'none',
            ], 'body'),
        ]);

        $ids = array_map(static fn ($f): string => $f->id, $findings);
        self::assertContains('insecure-csp', $ids);
    }

    public function testHstsIsNotRequiredOnPlainHttp(): void
    {
        $findings = $this->check->analyze(new Target('http://example.com'), [
            '/' => new Response(200, [
                'Content-Security-Policy' => "default-src 'self'",
                'X-Content-Type-Options' => 'nosniff',
                'X-Frame-Options' => 'DENY',
                'Referrer-Policy' => 'no-referrer',
                'X-Permitted-Cross-Domain-Policies' => 'none',
            ], 'body'),
        ]);

        $ids = array_map(static fn ($f): string => $f->id, $findings);
        self::assertNotContains('missing-header-strict-transport-security', $ids);
    }

    public function testACookieNamedSecureIsNotMistakenForTheSecureAttribute(): void
    {
        $findings = $this->check->analyze(new Target('https://example.com'), [
            '/' => new Response(200, ['Set-Cookie' => 'secure_session=abc; path=/'], 'body'),
        ]);

        $cookie = null;
        foreach ($findings as $finding) {
            if (str_starts_with($finding->id, 'cookie-flags-')) {
                $cookie = $finding;
                break;
            }
        }

        self::assertNotNull($cookie, 'the cookie must be reported');
        self::assertStringContainsString('missing Secure', $cookie->title);
    }

    public function testACookieCarryingEveryFlagIsNotReported(): void
    {
        $findings = $this->check->analyze(new Target('https://example.com'), [
            '/' => new Response(200, ['Set-Cookie' => 'session=abc; Secure; HttpOnly; SameSite=Lax'], 'body'),
        ]);

        foreach ($findings as $finding) {
            self::assertStringStartsNotWith('cookie-flags-', $finding->id);
        }
    }
}
