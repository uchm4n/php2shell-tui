<?php

declare(strict_types=1);

namespace Php2ShellTui\Tests\Unit;

use Php2ShellTui\PhpVersionAssessment;
use Php2ShellTui\PhpVersionDb;
use Php2ShellTui\Severity;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PhpVersionAssessmentTest extends TestCase
{
    private PhpVersionDb $db;

    protected function setUp(): void
    {
        $this->db = new PhpVersionDb(__DIR__ . '/../../src/Data/php-affected.json');
    }

    #[DataProvider('versions')]
    public function testItClassifiesVersions(string $version, string $state, Severity $severity): void
    {
        $assessment = PhpVersionAssessment::classify($this->db, $version);

        self::assertSame($state, $assessment['state']);
        self::assertSame($severity, $assessment['severity']);
    }

    public static function versions(): array
    {
        return [
            'end-of-life affected' => ['8.1.29', 'affected', Severity::Critical],
            'affected 8.2' => ['8.2.12-1ubuntu2.14', 'affected', Severity::Critical],
            'affected 8.3' => ['8.3.35', 'affected', Severity::Critical],
            'affected 8.4' => ['8.4.26', 'affected', Severity::Critical],
            'affected 8.5' => ['8.5.11', 'affected', Severity::Critical],
            'patched 8.2' => ['8.2.35', 'patched', Severity::Info],
            'patched 8.3' => ['8.3.36', 'patched', Severity::Info],
            'patched 8.4' => ['8.4.27', 'patched', Severity::Info],
            'patched 8.5' => ['8.5.12', 'patched', Severity::Info],
            'newer than the advisory' => ['8.6.0', 'newer', Severity::Low],
            'pre-release' => ['8.2.35RC1', 'prerelease', Severity::High],
            'unparseable' => ['not-a-version', 'unknown', Severity::High],
            'unknown branch' => ['6.0.0', 'unknown', Severity::High],
        ];
    }
}
