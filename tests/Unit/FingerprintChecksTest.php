<?php

declare(strict_types=1);

namespace Php2ShellTui\Tests\Unit;

use GuzzleHttp\Psr7\Response;
use Php2ShellTui\Check\AppFingerprint;
use Php2ShellTui\Check\WebshellIndicators;
use Php2ShellTui\Data\Reproduce;
use Php2ShellTui\Data\Wordlists;
use Php2ShellTui\Severity;
use Php2ShellTui\Target;
use PHPUnit\Framework\TestCase;

final class FingerprintChecksTest extends TestCase
{
    public function testWordpressIsIdentified(): void
    {
        $check = new AppFingerprint(new Reproduce(__DIR__ . '/../../data/repro'));
        $findings = $check->analyze(new Target('https://example.com'), [
            '/wp-includes/version.php' => new Response(200, [], "<?php \$wp_version = '6.5.2';"),
        ]);

        self::assertNotSame([], $findings);
        self::assertStringContainsString('WordPress', $findings[0]->title);
        self::assertSame(Severity::Info, $findings[0]->severity);
    }

    public function testTheBaselineBodyIsReadWithoutFataling(): void
    {
        $check = new AppFingerprint(new Reproduce(__DIR__ . '/../../data/repro'));
        $findings = $check->analyze(new Target('https://example.com'), [
            '/' => new Response(200, [], '<html><link href="/wp-content/themes/x/style.css"></html>'),
        ]);

        self::assertCount(1, $findings);
        self::assertSame('app-wordpress', $findings[0]->id);
    }

    public function testAWebshellIsOnlyConfirmedWhenTheBodyHasAShellPrimitive(): void
    {
        $check = new WebshellIndicators(
            new Wordlists(__DIR__ . '/../../data'),
            new Reproduce(__DIR__ . '/../../data/repro'),
        );

        $benign = $check->analyze(new Target('https://example.com'), [
            '/shell.php' => new Response(200, [], '<?php echo "hello"; ?>'),
        ]);
        self::assertSame([], $benign);

        $malicious = $check->analyze(new Target('https://example.com'), [
            '/shell.php' => new Response(200, [], "<?php system(\$_GET['c']); ?>"),
        ]);
        self::assertCount(1, $malicious);
        self::assertSame(Severity::High, $malicious[0]->severity);
    }

    public function testWebshellProbesCoverTheConfiguredUploadDirectories(): void
    {
        $check = new WebshellIndicators(
            new Wordlists(__DIR__ . '/../../data'),
            new Reproduce(__DIR__ . '/../../data/repro'),
        );

        $paths = $check->paths(new Target('https://example.com', null, ['/wp-content/uploads']), null);

        self::assertContains('/wp-content/uploads/shell.php', $paths);
        self::assertContains('/shell.php', $paths);
    }

    public function testAShellPrimitiveWithoutRequestInputIsNotAWebshell(): void
    {
        $check = new WebshellIndicators(
            new Wordlists(__DIR__ . '/../../data'),
            new Reproduce(__DIR__ . '/../../data/repro'),
        );

        $findings = $check->analyze(new Target('https://example.com'), [
            '/shell.php' => new Response(200, [], '<?php system("id"); ?>'),
        ]);

        self::assertSame([], $findings);
    }

    public function testAWebshellPathThatAnswers404IsNotAWebshell(): void
    {
        $check = new WebshellIndicators(
            new Wordlists(__DIR__ . '/../../data'),
            new Reproduce(__DIR__ . '/../../data/repro'),
        );

        $findings = $check->analyze(new Target('https://example.com'), [
            '/shell.php' => new Response(404, [], 'Not Found'),
        ]);

        self::assertSame([], $findings);
    }

    public function testEveryFindingCarriesAReproduceStep(): void
    {
        $fingerprint = new AppFingerprint(new Reproduce(__DIR__ . '/../../data/repro'));
        $webshell = new WebshellIndicators(
            new Wordlists(__DIR__ . '/../../data'),
            new Reproduce(__DIR__ . '/../../data/repro'),
        );

        $findings = array_merge(
            $fingerprint->analyze(new Target('https://example.com'), [
                '/wp-includes/version.php' => new Response(200, [], "<?php \$wp_version = '6.5.2';"),
            ]),
            $webshell->analyze(new Target('https://example.com'), [
                '/shell.php' => new Response(200, [], "<?php system(\$_POST['c']); ?>"),
            ]),
        );

        self::assertNotSame([], $findings);

        foreach ($findings as $finding) {
            self::assertNotEmpty($finding->reproduce, $finding->id . ' must have reproduce steps');
            self::assertNotSame('', trim($finding->exploit));
        }
    }
}
