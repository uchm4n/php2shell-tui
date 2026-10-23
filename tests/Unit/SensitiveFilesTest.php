<?php

declare(strict_types=1);

namespace Php2ShellTui\Tests\Unit;

use GuzzleHttp\Psr7\Response;
use Php2ShellTui\Check\SensitiveFiles;
use Php2ShellTui\Data\Reproduce;
use Php2ShellTui\Data\Wordlists;
use Php2ShellTui\Severity;
use Php2ShellTui\Target;
use PHPUnit\Framework\TestCase;

final class SensitiveFilesTest extends TestCase
{
    private SensitiveFiles $check;

    protected function setUp(): void
    {
        $this->check = new SensitiveFiles(
            new Wordlists(__DIR__ . '/../../src/Data'),
            new Reproduce(__DIR__ . '/../../src/Data/repro'),
        );
    }

    public function testAnExposedEnvFileIsHigh(): void
    {
        $findings = $this->check->analyze(new Target('https://legacy.example.com'), [
            '/.env' => new Response(200, [], "APP_KEY=base64:abc\nDB_PASSWORD=hunter2\n"),
        ]);

        self::assertCount(1, $findings);
        self::assertSame('sensitive-file-env', $findings[0]->id);
        self::assertSame(Severity::High, $findings[0]->severity);
        self::assertStringContainsString('APP_KEY', $findings[0]->evidence);
        self::assertNotEmpty($findings[0]->reproduce);
    }

    public function testTheExploitLineHasNoDoubleSlashForATargetUrlWithATrailingSlash(): void
    {
        $findings = $this->check->analyze(new Target('https://legacy.example.com/'), [
            '/.env' => new Response(200, [], "APP_KEY=abc\n"),
        ]);

        self::assertCount(1, $findings);
        self::assertStringContainsString('https://legacy.example.com/.env', $findings[0]->exploit);
        self::assertStringNotContainsString('https://legacy.example.com//.env', $findings[0]->exploit);
    }

    public function testTheRootDocumentIsNotAnExposedFile(): void
    {
        $findings = $this->check->analyze(new Target('https://legacy.example.com'), [
            '/' => new Response(200, [], '{"ok":true}'),
        ]);

        self::assertSame([], $findings);
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

    public function testTargetExtraPathsAreNotSensitiveFileProbes(): void
    {
        $paths = $this->check->paths(
            new Target('https://legacy.example.com', null, ['/admin', '/login']),
            null,
        );

        self::assertNotContains('/admin', $paths);
        self::assertNotContains('/login', $paths);
    }

    public function testAnEnvFileWithExportLinesIsStillReported(): void
    {
        $findings = $this->check->analyze(new Target('https://legacy.example.com'), [
            '/.env' => new Response(200, [], "export APP_KEY=base64:abc\n"),
        ]);

        self::assertCount(1, $findings);
    }

    public function testAnHtmlCatchAllPageIsNotALeakedEnvFile(): void
    {
        $findings = $this->check->analyze(new Target('https://legacy.example.com'), [
            '/.env' => new Response(200, ['Content-Type' => 'text/html'], '<html><body>Login token password</body></html>'),
        ]);

        self::assertSame([], $findings);
    }

    public function testAnHtmlCatchAllPageIsNotALeakedBackup(): void
    {
        $findings = $this->check->analyze(new Target('https://legacy.example.com'), [
            '/backup.zip' => new Response(200, [], '<html>Not found</html>'),
        ]);

        self::assertSame([], $findings);
    }

    public function testARealZipBackupIsReported(): void
    {
        $findings = $this->check->analyze(new Target('https://legacy.example.com'), [
            '/backup.zip' => new Response(200, [], "PK\x03\x04rest of the archive"),
        ]);

        self::assertCount(1, $findings);
        self::assertSame(Severity::High, $findings[0]->severity);
    }

    public function testAnExposedPhpinfoPageRequiresPhpinfoMarkers(): void
    {
        $benign = $this->check->analyze(new Target('https://legacy.example.com'), [
            '/phpinfo.php' => new Response(200, [], '<html>Login page</html>'),
        ]);
        $phpinfo = $this->check->analyze(new Target('https://legacy.example.com'), [
            '/phpinfo.php' => new Response(200, [], '<html><title>phpinfo()</title>PHP Version 8.2.29</html>'),
        ]);

        self::assertSame([], $benign);
        self::assertCount(1, $phpinfo);
    }

    public function testEveryFindingCarriesAReproduceStep(): void
    {
        $findings = $this->check->analyze(new Target('https://legacy.example.com'), [
            '/.env' => new Response(200, [], "APP_KEY=abc\n"),
            '/composer.lock' => new Response(200, [], '{"packages":[]}'),
        ]);

        foreach ($findings as $finding) {
            self::assertNotEmpty($finding->reproduce, $finding->id . ' must have reproduce steps');
            self::assertNotSame('', trim($finding->exploit));
        }
    }
}
