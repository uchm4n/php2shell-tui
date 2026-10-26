<?php

declare(strict_types=1);

namespace Php2ShellTui\Tests\Unit;

use GuzzleHttp\Psr7\Response;
use Php2ShellTui\Check\Php2Shell;
use Php2ShellTui\Data\Reproduce;
use Php2ShellTui\PhpVersionDb;
use Php2ShellTui\Severity;
use Php2ShellTui\Target;
use PHPUnit\Framework\TestCase;

final class Php2ShellTest extends TestCase
{
    private Reproduce $reproduce;
    private PhpVersionDb $db;
    private Target $target;

    protected function setUp(): void
    {
        $this->reproduce = new Reproduce(__DIR__ . '/../../src/Data/repro');
        $this->db = new PhpVersionDb(__DIR__ . '/../../src/Data/php-affected.json');
        $this->target = new Target('https://app.example/');
    }

    private function phpinfoBody(string $sapi = 'Apache 2.0 Handler'): string
    {
        $rows = '';
        foreach ([
            'Server API' => $sapi,
            'session.upload_progress.enabled' => 'On',
            'memory_limit' => '128M',
            'post_max_size' => '256M',
            'display_errors' => 'On',
            'session.use_strict_mode' => '0',
        ] as $name => $value) {
            $rows .= '<tr><td class="e">' . $name . '</td><td class="v">' . $value . '</td></tr>';
        }

        return '<html><body><h1>PHP Version 8.4.26</h1><table>' . $rows . '</table></body></html>';
    }

    public function testTheDefaultScanReportsTheExposureChecklist(): void
    {
        $check = new Php2Shell($this->reproduce, false, $this->db);
        $findings = $check->analyze($this->target, [
            '/' => new Response(200, [
                'X-Powered-By' => 'PHP/8.4.26',
                'Server' => 'Apache/2.4.69 (Debian)',
            ], 'OK'),
            '/phpinfo.php' => new Response(200, [], $this->phpinfoBody()),
        ]);

        $exposure = array_values(array_filter(
            $findings,
            static fn ($f): bool => $f->id === 'php2shell-exposure',
        ))[0];

        self::assertSame(Severity::High, $exposure->severity);
        self::assertStringContainsString('session.upload_progress.enabled=On', $exposure->evidence);
        self::assertStringContainsString('Apache 2.0 Handler', $exposure->evidence);
        self::assertStringContainsString('memory_limit=128M', $exposure->evidence);
        self::assertSame('PHP2Shell - exploitability assessment', $exposure->title);
        self::assertNotEmpty($exposure->reproduce);
    }

    public function testAFpmTargetIsMediumAndHasNoVerificationClaim(): void
    {
        $check = new Php2Shell($this->reproduce, false, $this->db);
        $findings = $check->analyze($this->target, [
            '/' => new Response(200, ['X-Powered-By' => 'PHP/8.4.26'], 'OK'),
            '/phpinfo.php' => new Response(200, [], $this->phpinfoBody('FPM/FastCGI')),
        ]);

        $exposure = array_values(array_filter(
            $findings,
            static fn ($f): bool => $f->id === 'php2shell-exposure',
        ))[0];

        self::assertSame(Severity::Medium, $exposure->severity);
        self::assertStringContainsString('FPM/FastCGI', $exposure->evidence);
    }

    public function testAPatchedVersionIsInformational(): void
    {
        $check = new Php2Shell($this->reproduce, false, $this->db);
        $findings = $check->analyze($this->target, [
            '/' => new Response(200, ['X-Powered-By' => 'PHP/8.5.12'], 'OK'),
        ]);

        self::assertSame(Severity::Info, $findings[0]->severity);
        self::assertStringContainsString('not applicable', $findings[0]->evidence);
    }

    public function testAPhpSignalWithoutAVersionIsHigh(): void
    {
        $check = new Php2Shell($this->reproduce, false, $this->db);
        $findings = $check->analyze($this->target, [
            '/' => new Response(200, ['Set-Cookie' => 'PHPSESSID=abc; path=/'], 'OK'),
        ]);

        self::assertSame(Severity::High, $findings[0]->severity);
        self::assertStringContainsString('undetermined', $findings[0]->title);
    }
}
