<?php

declare(strict_types=1);

namespace Php2Scan\Tests\Unit;

use GuzzleHttp\Psr7\Response;
use Php2Scan\Check\SensitiveFiles;
use Php2Scan\Data\Reproduce;
use Php2Scan\Data\Wordlists;
use Php2Scan\Severity;
use Php2Scan\Target;
use PHPUnit\Framework\TestCase;

final class SensitiveFilesTest extends TestCase
{
    private SensitiveFiles $check;

    protected function setUp(): void
    {
        $this->check = new SensitiveFiles(
            new Wordlists(__DIR__ . '/../../data'),
            new Reproduce(__DIR__ . '/../../data/repro'),
        );
    }

    public function testAnExposedEnvFileIsHigh(): void
    {
        $findings = $this->check->analyze(new Target('https://legacy.example.com'), [
            '/.env' => new Response(200, [], "APP_KEY=base64:abc\nDB_PASSWORD=hunter2\n"),
        ]);

        self::assertCount(1, $findings);
        self::assertSame(Severity::High, $findings[0]->severity);
        self::assertStringContainsString('APP_KEY', $findings[0]->evidence);
        self::assertNotEmpty($findings[0]->reproduce);
    }

    public function testA404IsNotAFinding(): void
    {
        $findings = $this->check->analyze(new Target('https://legacy.example.com'), [
            '/.env' => new Response(404, [], 'Not Found'),
        ]);

        self::assertSame([], $findings);
    }

    public function testALeakedManifestIsMedium(): void
    {
        $findings = $this->check->analyze(new Target('https://legacy.example.com'), [
            '/composer.lock' => new Response(200, [], '{"packages":[]}'),
        ]);

        self::assertSame(Severity::Medium, $findings[0]->severity);
    }

    public function testAnExposedDatabaseAdminConsoleIsHigh(): void
    {
        $adminer = $this->check->analyze(new Target('https://legacy.example.com'), [
            '/adminer.php' => new Response(200, [], '<?php // adminer'),
        ]);
        $phpmyadmin = $this->check->analyze(new Target('https://legacy.example.com'), [
            '/phpmyadmin/' => new Response(200, [], '<html>phpMyAdmin</html>'),
        ]);

        self::assertCount(1, $adminer);
        self::assertSame(Severity::High, $adminer[0]->severity);
        self::assertCount(1, $phpmyadmin);
        self::assertSame(Severity::High, $phpmyadmin[0]->severity);
    }

    public function testEveryFindingCarriesAReproduceStep(): void
    {
        $findings = $this->check->analyze(new Target('https://legacy.example.com'), [
            '/.env' => new Response(200, [], "APP_KEY=abc\n"),
            '/composer.lock' => new Response(200, [], '{}'),
        ]);

        foreach ($findings as $finding) {
            self::assertNotEmpty($finding->reproduce, $finding->id . ' must have reproduce steps');
            self::assertNotSame('', trim($finding->exploit));
        }
    }
}
