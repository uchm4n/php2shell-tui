<?php

declare(strict_types=1);

namespace Php2ShellTui\Tests\Unit;

use GuzzleHttp\Psr7\Response;
use Php2ShellTui\PhpFingerprint;
use PHPUnit\Framework\TestCase;

final class PhpFingerprintTest extends TestCase
{
    /**
     * @param string $sapi
     * @param array<string, string> $overrides
     */
    private function phpinfoBody(string $sapi = 'Apache 2.0 Handler', array $overrides = []): string
    {
        $ini = [
            'Server API' => $sapi,
            'session.upload_progress.enabled' => 'On',
            'memory_limit' => '128M',
            'post_max_size' => '256M',
            'display_errors' => 'On',
            'session.use_strict_mode' => '0',
        ] + $overrides;

        $rows = '';
        foreach ($ini as $name => $value) {
            $rows .= '<tr><td class="e">' . $name . '</td><td class="v">' . $value . '</td></tr>';
        }

        return '<html><body><h1>PHP Version 8.4.26</h1><table>' . $rows . '</table></body></html>';
    }

    public function testItExtractsVersionsFromHeadersBodyAndPhpinfo(): void
    {
        $responses = [
            '/' => new Response(200, [
                'X-Powered-By' => 'PHP/8.4.26',
                'Server' => 'Apache/2.4.69 (Debian) PHP/8.4.25',
            ], '<footer>PHP 8.4.24</footer>'),
            '/phpinfo.php' => new Response(200, [], $this->phpinfoBody()),
        ];

        $fingerprint = PhpFingerprint::fromResponses($responses);

        self::assertSame('8.4.26', $fingerprint->versions()[0]['version']);
        self::assertSame('X-Powered-By', $fingerprint->versions()[0]['source']);
        self::assertSame('8.4.26', $fingerprint->phpinfo()['ini']['php version']);
        self::assertSame('Apache 2.0 Handler', $fingerprint->sapi());
        self::assertSame('debian', $fingerprint->serverOs());
        self::assertSame('/phpinfo.php', $fingerprint->phpinfo()['url']);
        self::assertSame('On', $fingerprint->ini()['session.upload_progress.enabled']);
    }

    public function testItParsesTheIniRowsAndInfersSapiFromHeaders(): void
    {
        $responses = ['/' => new Response(200, [
            'Server' => 'nginx/1.24.0',
            'X-Powered-By' => 'PHP/8.5.11',
        ], 'OK')];

        $fingerprint = PhpFingerprint::fromResponses($responses);

        self::assertSame('inferred: fpm', $fingerprint->sapi());
        self::assertTrue($fingerprint->hasPhpSignal());
    }

    public function testItInfersModPhpFromApacheHeaders(): void
    {
        $responses = ['/' => new Response(200, [
            'Server' => 'Apache/2.4.69 (Debian)',
            'X-Powered-By' => 'PHP/8.4.26',
        ], 'OK')];

        self::assertSame('inferred: mod_php', PhpFingerprint::fromResponses($responses)->sapi());
    }

    public function testItFindsAVersionInTheBaselineBody(): void
    {
        $responses = ['/' => new Response(200, [], '<p>PHP Version 7.4.33</p>')];

        self::assertSame('7.4.33', PhpFingerprint::fromResponses($responses)->versions()[0]['version']);
    }

    public function testThePathsAreTheThreeKnownProbes(): void
    {
        self::assertSame(['/', '/phpinfo.php', '/info.php'], PhpFingerprint::paths());
    }
}
