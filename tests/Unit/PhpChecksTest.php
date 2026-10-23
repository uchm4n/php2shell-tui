<?php

declare(strict_types=1);

namespace Php2ShellTui\Tests\Unit;

use GuzzleHttp\Psr7\Response;
use Php2ShellTui\Check\PhpDetection;
use Php2ShellTui\Check\PhpVersion;
use Php2ShellTui\Data\Reproduce;
use Php2ShellTui\PhpVersionDb;
use Php2ShellTui\Severity;
use Php2ShellTui\Target;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PhpChecksTest extends TestCase
{
    private Target $target;
    private Reproduce $reproduce;
    private PhpVersionDb $db;

    protected function setUp(): void
    {
        $this->target = new Target('https://legacy.example.com');
        $this->reproduce = new Reproduce(__DIR__ . '/../../src/Data/repro');
        $this->db = new PhpVersionDb(__DIR__ . '/../../src/Data/php-affected.json');
    }

    public function testItDetectsPhpFromThePoweredByHeader(): void
    {
        $findings = (new PhpDetection($this->reproduce))->analyze($this->target, [
            '/' => new Response(200, ['X-Powered-By' => 'PHP/8.1.29'], 'body'),
        ]);

        self::assertCount(1, $findings);
        self::assertSame('php_presence', $findings[0]->id);
        self::assertSame(Severity::Info, $findings[0]->severity);
        self::assertStringContainsString('X-Powered-By', $findings[0]->evidence);
        self::assertNotSame('', $findings[0]->exploit);
        self::assertNotEmpty($findings[0]->reproduce);
    }

    public function testItReportsNoPhpWhenNoSignalFires(): void
    {
        $findings = (new PhpDetection($this->reproduce))->analyze($this->target, [
            '/' => new Response(200, [], '<html>hi</html>'),
        ]);

        self::assertCount(1, $findings);
        self::assertStringContainsString('No PHP', $findings[0]->title);
        self::assertNotEmpty($findings[0]->reproduce);
    }

    public function testA404BaselineStillRevealsThePhpVersion(): void
    {
        $findings = (new PhpVersion($this->db, $this->reproduce))->analyze($this->target, [
            '/' => new Response(404, ['Server' => 'Apache/2.4.58 (Unix) PHP/8.1.29'], '<h1>Not Found</h1>'),
        ]);

        self::assertSame(Severity::Critical, $findings[0]->severity);
        self::assertStringContainsString('8.1.29', $findings[0]->evidence);
    }

    public function testItFlagsAnAffectedVersionAsCritical(): void
    {
        $findings = (new PhpVersion($this->db, $this->reproduce))->analyze($this->target, [
            '/' => new Response(200, ['X-Powered-By' => 'PHP/8.1.29'], 'body'),
        ]);

        self::assertCount(1, $findings);
        self::assertSame(Severity::Critical, $findings[0]->severity);
        self::assertStringContainsString('8.1.29', $findings[0]->evidence);
        self::assertStringContainsString('8.2.35', $findings[0]->evidence);
        self::assertStringContainsString('backport', $findings[0]->evidence);
        self::assertNotEmpty($findings[0]->reproduce);
    }

    public function testAVersionNewerThanTheAdvisoryIsLowNotPatched(): void
    {
        $findings = (new PhpVersion($this->db, $this->reproduce))->analyze($this->target, [
            '/' => new Response(200, ['X-Powered-By' => 'PHP/8.6.0'], 'body'),
        ]);

        self::assertSame(Severity::Low, $findings[0]->severity);
    }

    public function testAPatchedVersionIsInformational(): void
    {
        $findings = (new PhpVersion($this->db, $this->reproduce))->analyze($this->target, [
            '/' => new Response(200, ['X-Powered-By' => 'PHP/8.5.12'], 'body'),
        ]);

        self::assertSame(Severity::Info, $findings[0]->severity);
    }

    public function testAnUnknownVersionIsHighNotCritical(): void
    {
        $findings = (new PhpVersion($this->db, $this->reproduce))->analyze($this->target, [
            '/' => new Response(200, ['Set-Cookie' => 'PHPSESSID=abc; path=/'], 'body'),
        ]);

        self::assertSame(Severity::High, $findings[0]->severity);
        self::assertStringContainsString('php -v', implode("\n", $findings[0]->reproduce));
    }

    public function testAnUnparseableVersionIsTreatedAsUnknown(): void
    {
        $findings = (new PhpVersion($this->db, $this->reproduce))->analyze($this->target, [
            '/' => new Response(200, ['X-Powered-By' => 'PHP/not-a-version'], 'body'),
        ]);

        self::assertSame(Severity::High, $findings[0]->severity);
    }

    public static function preReleases(): array
    {
        return [
            ['8.2.35RC1'],
            ['8.3.0-dev'],
            ['8.2.35-rc1'],
        ];
    }

    /**
     * A pre-release is never evidence of a stable fix.
     */
    #[DataProvider('preReleases')]
    public function testAPreReleaseIsUndeterminedNotPatched(string $version): void
    {
        $findings = (new PhpVersion($this->db, $this->reproduce))->analyze($this->target, [
            '/' => new Response(200, ['X-Powered-By' => 'PHP/' . $version], 'body'),
        ]);

        self::assertSame(Severity::High, $findings[0]->severity);
        self::assertStringContainsString('undetermined', $findings[0]->title);
        self::assertStringContainsString($version, $findings[0]->evidence);
    }

    public function testADistributionSuffixIsNotAPreRelease(): void
    {
        $findings = (new PhpVersion($this->db, $this->reproduce))->analyze($this->target, [
            '/' => new Response(200, ['X-Powered-By' => 'PHP/8.2.12-1ubuntu2.14'], 'body'),
        ]);

        self::assertSame(Severity::Critical, $findings[0]->severity);
        self::assertStringContainsString('8.2.12', $findings[0]->evidence);
    }

    public function testItJudgesOnTheWorstAdvertisedVersion(): void
    {
        $findings = (new PhpVersion($this->db, $this->reproduce))->analyze($this->target, [
            '/' => new Response(200, [
                'X-Powered-By' => 'PHP/8.5.12',
                'Server' => 'Apache/2.4.58 (Unix) PHP/8.1.29',
            ], 'body'),
        ]);

        self::assertSame(Severity::Critical, $findings[0]->severity);
        self::assertStringContainsString('8.1.29', $findings[0]->evidence);
    }

    public function testThePhpinfoBodyIsAVersionSource(): void
    {
        $findings = (new PhpVersion($this->db, $this->reproduce))->analyze($this->target, [
            '/' => new Response(200, [], 'homepage'),
            '/phpinfo.php' => new Response(200, [], '<title>phpinfo() - PHP Version 8.1.29</title>'),
        ]);

        self::assertSame(Severity::Critical, $findings[0]->severity);
        self::assertStringContainsString('8.1.29', $findings[0]->evidence);
        self::assertStringContainsString('/phpinfo.php', $findings[0]->evidence);
    }

    public function testAPhpinfoBodyThatIsNotFoundIsNotAVersionSource(): void
    {
        $findings = (new PhpVersion($this->db, $this->reproduce))->analyze($this->target, [
            '/' => new Response(200, ['X-Powered-By' => 'PHP/8.5.12'], 'body'),
            '/phpinfo.php' => new Response(404, [], '<h1>Not Found</h1>PHP Version 8.1.29'),
        ]);

        self::assertSame(Severity::Info, $findings[0]->severity);
    }

    public function testTheVersionFindingIsInformationalWithoutPhp(): void
    {
        $findings = (new PhpVersion($this->db, $this->reproduce))->analyze($this->target, [
            '/' => new Response(200, [], '<html>hi</html>'),
        ]);

        self::assertSame(Severity::Info, $findings[0]->severity);
        self::assertStringContainsString('no PHP', $findings[0]->title);
        self::assertNotEmpty($findings[0]->reproduce);
    }

    public function testTheChecksAskForThePathsTheyNeed(): void
    {
        self::assertSame(['/'], (new PhpDetection($this->reproduce))->paths($this->target, null));
        self::assertSame(
            ['/', '/phpinfo.php', '/info.php'],
            (new PhpVersion($this->db, $this->reproduce))->paths($this->target, null),
        );
    }

    public function testAnExpressPoweredByHeaderIsNotAPhpSignal(): void
    {
        $findings = (new PhpDetection($this->reproduce))->analyze($this->target, [
            '/' => new Response(200, ['X-Powered-By' => 'Express'], '<html>hi</html>'),
        ]);

        self::assertSame('No PHP signal detected', $findings[0]->title);
        self::assertStringNotContainsString('Express', $findings[0]->evidence);
    }

    public function testHeaderSignalsIgnoreTheBody(): void
    {
        $response = new Response(200, [], 'Powered by PHP');

        self::assertSame([], PhpDetection::headerSignals($response));
        self::assertNotEmpty(PhpDetection::signals($response));
        self::assertSame('Powered by PHP', (string) $response->getBody());
    }

    public function testHeaderSignalsFindPhpHeaders(): void
    {
        $signals = PhpDetection::headerSignals(new Response(200, [
            'X-Powered-By' => 'PHP/8.4.26',
            'Server' => 'Apache/2.4.58 (Unix) PHP/8.4.26',
            'Set-Cookie' => 'PHPSESSID=abc; path=/',
        ]));

        self::assertContains('X-Powered-By: PHP/8.4.26', $signals);
        self::assertContains('Server: Apache/2.4.58 (Unix) PHP/8.4.26', $signals);
        self::assertContains('Set-Cookie: PHPSESSID', $signals);
    }

    public function testALaravelSessionCookieIsNotAPhpSignal(): void
    {
        $findings = (new PhpDetection($this->reproduce))->analyze($this->target, [
            '/' => new Response(200, ['Set-Cookie' => 'laravel_session=abc; path=/'], '<html>hi</html>'),
        ]);

        self::assertSame('No PHP signal detected', $findings[0]->title);
        self::assertStringContainsString('full proof', $findings[0]->exploit);
    }

    public function testThePositivePresenceFindingNamesTheBranchFixes(): void
    {
        $findings = (new PhpDetection($this->reproduce))->analyze($this->target, [
            '/' => new Response(200, ['X-Powered-By' => 'PHP/8.4.26'], 'body'),
        ]);

        self::assertStringNotContainsString('every PHP release before 8.2.35', $findings[0]->exploit);
        self::assertStringContainsString('8.3.36', $findings[0]->exploit);
        self::assertStringContainsString('8.4.27', $findings[0]->exploit);
    }

    public function testTheVersionFindingDoesNotClaimTheHostDoesNotRunPhp(): void
    {
        $findings = (new PhpVersion($this->db, $this->reproduce))->analyze($this->target, [
            '/' => new Response(200, [], '<html>hi</html>'),
        ]);

        self::assertStringContainsStringIgnoringCase('no PHP signal', $findings[0]->title);
        self::assertStringNotContainsString('does not run PHP', $findings[0]->exploit);
        self::assertStringContainsString('full proof', $findings[0]->exploit);
    }

    public function testTheAffectedFindingDoesNotNameFpmAsTheVerifiedWorker(): void
    {
        $findings = (new PhpVersion($this->db, $this->reproduce))->analyze($this->target, [
            '/' => new Response(200, ['X-Powered-By' => 'PHP/8.1.29'], 'body'),
        ]);

        self::assertStringNotContainsString('PHP-FPM worker', $findings[0]->exploit);
        self::assertStringContainsString('mod_php', $findings[0]->exploit);
    }

    public function testTheAffectedEvidenceUsesFixedInNotContradictoryWording(): void
    {
        $findings = (new PhpVersion($this->db, $this->reproduce))->analyze($this->target, [
            '/' => new Response(200, ['X-Powered-By' => 'PHP/8.2.12-1ubuntu2.14'], 'body'),
        ]);

        self::assertStringContainsString('affected; fixed in 8.2.35', $findings[0]->evidence);
        self::assertStringNotContainsString('affected - patched', $findings[0]->evidence);
    }
}
