<?php

declare(strict_types=1);

namespace Php2ShellTui\Tests\Unit;

use GuzzleHttp\Psr7\Response;
use Php2ShellTui\Check\Php2Shell;
use Php2ShellTui\Data\Reproduce;
use Php2ShellTui\Finding;
use Php2ShellTui\PhpVersionDb;
use Php2ShellTui\Poc\Php2ShellPoc;
use Php2ShellTui\Poc\PocPlan;
use Php2ShellTui\Poc\PocResult;
use Php2ShellTui\Poc\Profile;
use Php2ShellTui\Poc\ProfileCatalog;
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

    private function phpinfoBody(string $sapi = 'Apache 2.0 Handler', array $overrides = [], string $version = '8.4.26'): string
    {
        $values = array_merge([
            'session.upload_progress.enabled' => 'On',
            'memory_limit' => '128M',
            'post_max_size' => '256M',
            'display_errors' => 'On',
            'session.use_strict_mode' => '0',
            'session.use_only_cookies' => 'On',
            'session.serialize_handler' => 'php',
        ], $overrides);
        $values['Server API'] = $sapi;

        $rows = '';
        foreach ($values as $name => $value) {
            $rows .= '<tr><td class="e">' . $name . '</td><td class="v">' . $value . '</td></tr>';
        }

        return '<html><body><h1>PHP Version ' . $version . '</h1><table>' . $rows . '</table></body></html>';
    }

    /**
     * @param array<string, string> $overrides
     * @return array<string, Response>
     */
    private function responses(array $overrides = []): array
    {
        $version = $overrides['version'] ?? '8.4.26';
        $server = $overrides['server'] ?? 'Apache/2.4.69 (Debian)';
        $sapi = $overrides['sapi'] ?? 'Apache 2.0 Handler';
        $ini = $overrides;
        unset($ini['version'], $ini['server'], $ini['sapi']);

        return [
            '/' => new Response(200, [
                'X-Powered-By' => 'PHP/' . $version,
                'Server' => $server,
            ], 'OK'),
            '/phpinfo.php' => new Response(200, [], $this->phpinfoBody($sapi, $ini, $version)),
        ];
    }

    /**
     * @param list<array{0: string, 1: ?int, 2: ?int}> $calls
     */
    private function runner(array &$calls, ?PocResult $result = null): \Closure
    {
        $result ??= new PocResult(true, 'RCE confirmed', 'ABCDEFG', null, 'https://app.example/p');

        return static function (Target $target, Profile $profile, PocPlan $plan) use (&$calls, $result): PocResult {
            $calls[] = [$profile->id(), $plan->memoryLimitMb, $plan->workers];

            return $result;
        };
    }

    /**
     * @param list<array{0: string, 1: ?int, 2: ?int}> $calls
     */
    private function check(array &$calls, ?PocPlan $plan = null, ?PocResult $result = null): Php2Shell
    {
        return new Php2Shell(
            $this->reproduce,
            true,
            $this->db,
            new Php2ShellPoc(),
            new ProfileCatalog(__DIR__ . '/../../src/Data/poc'),
            $plan ?? new PocPlan(workers: 1, memoryLimitMb: 128),
            null,
            $this->runner($calls, $result),
        );
    }

    /**
     * @param list<Finding> $findings
     */
    private function inconclusive(array $findings): Finding
    {
        $matches = array_values(array_filter(
            $findings,
            static fn (Finding $finding): bool => $finding->id === 'php2shell-poc-inconclusive',
        ));

        self::assertNotEmpty($matches);

        return $matches[0];
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

    public function testItReportsCriticalOnlyForAConfirmedProof(): void
    {
        $calls = [];
        $findings = $this->check($calls)->analyze($this->target, $this->responses());

        self::assertSame([['php-8.4.26-bookworm-amd64', 128, 1]], $calls);
        $rce = array_values(array_filter(
            $findings,
            static fn (Finding $finding): bool => $finding->id === 'php2shell-rce',
        ))[0];
        self::assertSame(Severity::Critical, $rce->severity);
        self::assertStringContainsString('ABCDEFG', $rce->evidence);
        self::assertStringContainsString('https://app.example/p', $rce->evidence);
    }

    public function testARealModPhpSapiIsRecognised(): void
    {
        $calls = [];
        $findings = $this->check($calls)->analyze(
            $this->target,
            $this->responses(['sapi' => 'Apache 2 Handler']),
        );

        self::assertCount(1, $calls);
        self::assertSame(
            1,
            count(array_filter($findings, static fn (Finding $f): bool => $f->id === 'php2shell-rce')),
        );
    }

    public function testItSendsNoPayloadForAKnownFpmTarget(): void
    {
        $calls = [];
        $findings = $this->check($calls)->analyze($this->target, $this->responses(['sapi' => 'FPM/FastCGI']));

        self::assertSame([], $calls);
        self::assertStringContainsString('mod_php', $this->inconclusive($findings)->evidence);
    }

    public function testItSendsNoPayloadWhenDisplayErrorsIsOff(): void
    {
        $calls = [];
        $findings = $this->check($calls)->analyze($this->target, $this->responses(['display_errors' => 'Off']));

        self::assertSame([], $calls);
        self::assertStringContainsString('display_errors', $this->inconclusive($findings)->evidence);
    }

    public function testItSendsNoPayloadWhenUploadProgressIsOff(): void
    {
        $calls = [];
        $findings = $this->check($calls)->analyze(
            $this->target,
            $this->responses(['session.upload_progress.enabled' => 'Off']),
        );

        self::assertSame([], $calls);
        self::assertStringContainsString('session.upload_progress', $this->inconclusive($findings)->evidence);
    }

    public function testItSendsNoPayloadWhenStrictModeIsOn(): void
    {
        $calls = [];
        $findings = $this->check($calls)->analyze(
            $this->target,
            $this->responses(['session.use_strict_mode' => '1']),
        );

        self::assertSame([], $calls);
        self::assertStringContainsString('use_strict_mode', $this->inconclusive($findings)->evidence);
    }

    public function testItSendsNoPayloadWhenMemoryIsUnlimited(): void
    {
        $calls = [];
        $findings = $this->check(
            $calls,
            new PocPlan(workers: 1, memoryLimitMb: null),
        )->analyze($this->target, $this->responses(['memory_limit' => '-1']));

        self::assertSame([], $calls);
        self::assertStringContainsString('memory_limit', $this->inconclusive($findings)->evidence);
    }

    public function testItSendsNoPayloadWhenPostMaxIsBelowTheOomSize(): void
    {
        $calls = [];
        $findings = $this->check(
            $calls,
            new PocPlan(workers: 1, memoryLimitMb: 128),
        )->analyze($this->target, $this->responses(['post_max_size' => '8M']));

        self::assertSame([], $calls);
        self::assertStringContainsString('post_max_size', $this->inconclusive($findings)->evidence);
    }

    public function testItSendsNoPayloadWithoutWorkers(): void
    {
        $calls = [];
        $findings = $this->check(
            $calls,
            new PocPlan(workers: null, memoryLimitMb: 128),
        )->analyze($this->target, $this->responses());

        self::assertSame([], $calls);
        self::assertStringContainsString('workers', $this->inconclusive($findings)->evidence);
    }

    public function testItRefusesWhenTheVersionHasMultipleArchitectures(): void
    {
        $calls = [];
        $findings = $this->check($calls)->analyze(
            $this->target,
            $this->responses(['version' => '8.5.11']),
        );

        self::assertSame([], $calls);
        self::assertStringContainsString('arch', $this->inconclusive($findings)->evidence);
    }

    public function testItRefusesAnUncalibratedVersion(): void
    {
        $calls = [];
        $findings = $this->check($calls)->analyze(
            $this->target,
            $this->responses(['version' => '7.4.33']),
        );

        self::assertSame([], $calls);
        self::assertStringContainsString('no calibrated profile', $this->inconclusive($findings)->evidence);
    }

    public function testItRefusesADistroMismatch(): void
    {
        $calls = [];
        $findings = $this->check($calls)->analyze(
            $this->target,
            $this->responses(['server' => 'Apache/2.4.69 (Ubuntu)']),
        );

        self::assertSame([], $calls);
        self::assertStringContainsString('debian', $this->inconclusive($findings)->evidence);
    }

    public function testItReportsAFailedProofWithoutClaimingSafety(): void
    {
        $calls = [];
        $findings = $this->check(
            $calls,
            null,
            new PocResult(false, 'no proof'),
        )->analyze($this->target, $this->responses());

        self::assertCount(1, $calls);
        $info = $this->inconclusive($findings);
        self::assertStringContainsString('no proof', $info->evidence);
        self::assertStringContainsString('do not treat this as safe', $info->exploit);
    }

    public function testAPatchedHeaderIsNotOverriddenByALowConfidenceBodyVersion(): void
    {
        $calls = [];
        $findings = $this->check($calls)->analyze($this->target, [
            '/' => new Response(200, ['X-Powered-By' => 'PHP/8.4.27'], '<p>PHP Version 8.4.26</p>'),
        ]);

        self::assertSame([], $calls);
        self::assertStringContainsString('8.4.27', $this->inconclusive($findings)->evidence);
    }

    public function testConflictingTrustedVersionsAreRefused(): void
    {
        $calls = [];
        $findings = $this->check($calls)->analyze($this->target, [
            '/' => new Response(200, [
                'X-Powered-By' => 'PHP/8.4.27',
                'Server' => 'Apache/2.4.69 (Debian) PHP/8.4.26',
            ], 'OK'),
        ]);

        self::assertSame([], $calls);
        self::assertStringContainsString('conflicting', $this->inconclusive($findings)->evidence);
    }

    public function testALowConfidenceBodyVersionIsNotAutoVerified(): void
    {
        $calls = [];
        $findings = $this->check($calls)->analyze($this->target, [
            '/' => new Response(200, [], '<p>PHP Version 8.4.26</p>'),
        ]);

        self::assertSame([], $calls);
        self::assertStringContainsString('low-confidence', $this->inconclusive($findings)->evidence);
    }

    public function testAContradictoryVersionOverrideIsRefused(): void
    {
        $calls = [];
        $findings = $this->check(
            $calls,
            new PocPlan(version: '8.4.26', workers: 1, memoryLimitMb: 128),
        )->analyze($this->target, $this->responses(['version' => '8.5.12']));

        self::assertSame([], $calls);
        self::assertStringContainsString('8.5.12', $this->inconclusive($findings)->evidence);
    }

    public function testAHiddenVersionOverrideSelectsTheProfile(): void
    {
        $calls = [];
        $findings = $this->check(
            $calls,
            new PocPlan(version: '8.4.26', workers: 1, memoryLimitMb: 128),
        )->analyze($this->target, [
            '/' => new Response(200, ['Server' => 'Apache/2.4.69 (Debian)'], 'OK'),
        ]);

        self::assertSame([['php-8.4.26-bookworm-amd64', 128, 1]], $calls);
        self::assertSame(
            1,
            count(array_filter($findings, static fn (Finding $f): bool => $f->id === 'php2shell-rce')),
        );
    }

    public function testTheExposureNamesTheMatchingCalibratedProfile(): void
    {
        $check = new Php2Shell(
            $this->reproduce,
            false,
            $this->db,
            null,
            new ProfileCatalog(__DIR__ . '/../../src/Data/poc'),
        );
        $findings = $check->analyze($this->target, $this->responses());
        $exposure = array_values(array_filter(
            $findings,
            static fn (Finding $f): bool => $f->id === 'php2shell-exposure',
        ))[0];

        self::assertStringContainsString('profile=php-8.4.26-bookworm-amd64', $exposure->evidence);
    }

    public function testUnknownMemoryDoesNotCloseThePostMaxCheck(): void
    {
        $check = new Php2Shell(
            $this->reproduce,
            false,
            $this->db,
            null,
            new ProfileCatalog(__DIR__ . '/../../src/Data/poc'),
        );
        $findings = $check->analyze($this->target, $this->responses([
            'memory_limit' => '',
            'post_max_size' => '256M',
        ]));

        self::assertSame(Severity::High, $findings[0]->severity);
        self::assertStringContainsString('post_max_size=256M', $findings[0]->evidence);
        self::assertStringNotContainsString('post_max_size=256M (NOT MET)', $findings[0]->evidence);
    }

    public function testTheSameOomBoundaryIsUsedAtEightMiB(): void
    {
        $calls = [];
        $findings = $this->check(
            $calls,
            new PocPlan(workers: 1, memoryLimitMb: 8),
        )->analyze($this->target, $this->responses([
            'memory_limit' => '8M',
            'post_max_size' => '12M',
        ]));

        self::assertSame([], $calls);
        self::assertStringContainsString('post_max_size', $this->inconclusive($findings)->evidence);

        $calls = [];
        $findings = $this->check(
            $calls,
            new PocPlan(workers: 1, memoryLimitMb: 8),
        )->analyze($this->target, $this->responses([
            'memory_limit' => '8M',
            'post_max_size' => '16M',
        ]));

        self::assertCount(1, $calls);
        self::assertSame(
            1,
            count(array_filter($findings, static fn (Finding $f): bool => $f->id === 'php2shell-rce')),
        );
    }

    public function testTheSameOomBoundaryIsUsedAt128MiB(): void
    {
        $calls = [];
        $findings = $this->check(
            $calls,
            new PocPlan(workers: 1, memoryLimitMb: 128),
        )->analyze($this->target, $this->responses([
            'memory_limit' => '128M',
            'post_max_size' => '140M',
        ]));

        self::assertSame([], $calls);
        self::assertStringContainsString('post_max_size', $this->inconclusive($findings)->evidence);

        $calls = [];
        $findings = $this->check(
            $calls,
            new PocPlan(workers: 1, memoryLimitMb: 128),
        )->analyze($this->target, $this->responses([
            'memory_limit' => '128M',
            'post_max_size' => '141M',
        ]));

        self::assertCount(1, $calls);
        self::assertSame(
            1,
            count(array_filter($findings, static fn (Finding $f): bool => $f->id === 'php2shell-rce')),
        );
    }

    public function testInferredModPhpIsReportedAsInferred(): void
    {
        $calls = [];
        $findings = $this->check($calls)->analyze($this->target, [
            '/' => new Response(200, [
                'X-Powered-By' => 'PHP/8.4.26',
                'Server' => 'Apache/2.4.69 (Debian)',
            ], 'OK'),
        ]);
        $exposure = array_values(array_filter(
            $findings,
            static fn (Finding $f): bool => $f->id === 'php2shell-exposure',
        ))[0];

        self::assertStringContainsString('SAPI: inferred: mod_php', $exposure->evidence);
    }
}
