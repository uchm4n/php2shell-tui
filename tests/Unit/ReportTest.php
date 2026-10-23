<?php

declare(strict_types=1);

namespace Php2ShellTui\Tests\Unit;

use Php2ShellTui\Config;
use Php2ShellTui\Finding;
use Php2ShellTui\Report\Report;
use Php2ShellTui\ScanResult;
use Php2ShellTui\Severity;
use PHPUnit\Framework\TestCase;

final class ReportTest extends TestCase
{
    private function scanResult(): ScanResult
    {
        return new ScanResult(
            findings: [
                new Finding(
                    id: 'php2shell-version',
                    title: 'PHP2Shell · CVE-2026-109618',
                    severity: Severity::Critical,
                    target: 'legacy.example.com',
                    evidence: 'PHP 8.1.29 detected via X-Powered-By (confidence: high); affected; this branch has no fixed release, upgrade to 8.2.35 or newer.',
                    exploit: 'The verified public chain is Apache prefork + mod_php; FPM requires a different, unverified route.',
                    reproduce: ['curl -sI https://legacy.example.com/ | grep -i x-powered-by'],
                ),
                new Finding(
                    id: 'sensitive-file-env',
                    title: 'Exposed .env',
                    severity: Severity::High,
                    target: 'legacy.example.com',
                    evidence: 'HTTP 200, 42 bytes, contains credential-looking keys.',
                    exploit: 'curl https://legacy.example.com/.env and read the leaked credentials.',
                    reproduce: ['curl -sS https://legacy.example.com/.env | head -20'],
                ),
            ],
            unreachable: [['target' => 'dead.example.com', 'error' => 'Connection refused']],
            unscannable: [['target' => 'waf.example.com', 'status' => 403]],
            duration: 1.25,
        );
    }

    public function testTextIncludesEveryPartOfEveryFinding(): void
    {
        $report = new Report($this->scanResult(), Config::fromArray(['targets' => ['https://legacy.example.com']]));
        $text = $report->text();

        self::assertStringContainsString('CRITICAL', $text);
        self::assertStringContainsString('legacy.example.com', $text);
        self::assertStringContainsString('How to exploit:', $text);
        self::assertStringContainsString('curl -sS https://legacy.example.com/.env', $text);
        self::assertStringContainsString('dead.example.com', $text);
        self::assertStringContainsString('waf.example.com', $text);
    }

    public function testJsonIsValidAndCarriesTheFindings(): void
    {
        $report = new Report($this->scanResult(), Config::fromArray(['targets' => ['https://legacy.example.com']]));
        $decoded = json_decode($report->json(), true, 512, JSON_THROW_ON_ERROR);

        self::assertCount(2, $decoded['findings']);
        self::assertSame('php2shell-version', $decoded['findings'][0]['id']);
        self::assertSame('critical', $decoded['findings'][0]['severity']);
        self::assertSame(1, $decoded['summary']['critical']);
    }

    public function testTheTextReportOmitsFindingsBelowMinSeverity(): void
    {
        $config = Config::fromArray([
            'targets' => ['https://legacy.example.com'],
            'options' => ['min_severity' => 'critical'],
        ]);
        $report = new Report($this->scanResult(), $config);
        $text = $report->text();

        self::assertStringContainsString('PHP2Shell', $text);
        self::assertStringNotContainsString('Exposed .env', $text);
    }

    public function testTheJsonReportKeepsTheFindingsBelowMinSeverity(): void
    {
        $config = Config::fromArray([
            'targets' => ['https://legacy.example.com'],
            'options' => ['min_severity' => 'critical'],
        ]);
        $report = new Report($this->scanResult(), $config);
        $decoded = json_decode($report->json(), true, 512, JSON_THROW_ON_ERROR);

        // The threshold only filters the text and markdown reports.
        self::assertCount(2, $decoded['findings']);
        self::assertSame('php2shell-version', $decoded['findings'][0]['id']);
        self::assertSame('sensitive-file-env', $decoded['findings'][1]['id']);
        self::assertSame('high', $decoded['findings'][1]['severity']);
        self::assertStringContainsString('PHP2Shell', $report->text());
        self::assertStringNotContainsString('Exposed .env', $report->text());
    }

    public function testMarkdownIncludesTheReproduceSteps(): void
    {
        $report = new Report($this->scanResult(), Config::fromArray(['targets' => ['https://legacy.example.com']]));
        $markdown = $report->markdown();

        self::assertStringContainsString('## CRITICAL', $markdown);
        self::assertStringContainsString('```bash', $markdown);
        self::assertStringContainsString('curl -sI https://legacy.example.com/', $markdown);
    }

    public function testTheTuiFormatFallsBackToText(): void
    {
        $report = new Report($this->scanResult(), Config::fromArray(['targets' => ['https://legacy.example.com']]));

        self::assertSame($report->text(), $report->render('tui'));
    }
}
