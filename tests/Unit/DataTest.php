<?php

declare(strict_types=1);

namespace Php2ShellTui\Tests\Unit;

use Php2ShellTui\Data\Reproduce;
use Php2ShellTui\Data\Wordlists;
use PHPUnit\Framework\TestCase;

final class DataTest extends TestCase
{
    private string $dataDir;

    protected function setUp(): void
    {
        $this->dataDir = __DIR__ . '/../../src/Data';
    }

    public function testWordlistsAreLoadedAndCleaned(): void
    {
        $wordlists = new Wordlists($this->dataDir);

        $sensitive = $wordlists->sensitivePaths();
        self::assertContains('.env', $sensitive);
        self::assertContains('.git/config', $sensitive);
        self::assertNotContains('', $sensitive);

        self::assertContains('shell.php', $wordlists->webshellPaths());
        self::assertContains(443, $wordlists->openPorts());
        self::assertContains(3306, $wordlists->openPorts());
    }

    public function testReproduceStepsAreSplitOnBlankLinesAndSubstituted(): void
    {
        $reproduce = new Reproduce($this->dataDir . '/repro');
        $steps = $reproduce->steps('sensitive-file-env', 'https://legacy.example.com');

        self::assertGreaterThanOrEqual(2, count($steps));
        self::assertStringContainsString('https://legacy.example.com/.env', $steps[0]);
        self::assertStringNotContainsString('{url}', implode("\n", $steps));
    }

    public function testAMissingReproduceFileYieldsNoSteps(): void
    {
        $reproduce = new Reproduce($this->dataDir . '/repro');

        self::assertSame([], $reproduce->steps('does-not-exist', 'https://example.com'));
    }

    public function testThePathPlaceholderIsSubstituted(): void
    {
        $reproduce = new Reproduce($this->dataDir . '/repro');
        $steps = $reproduce->steps('sensitive-file', 'https://legacy.example.com', 'legacy.example.com', ['path' => '.env']);

        self::assertStringContainsString('https://legacy.example.com/.env', $steps[0]);
        self::assertStringNotContainsString('{path}', implode("\n", $steps));
    }

    public function testEveryReproduceFileYieldsAtLeastOneStep(): void
    {
        $reproduce = new Reproduce($this->dataDir . '/repro');
        $files = glob($this->dataDir . '/repro/*.md') ?: [];

        self::assertNotSame([], $files, 'there must be reproduce files to sweep');

        foreach ($files as $file) {
            $id = basename($file, '.md');

            self::assertNotSame(
                [],
                $reproduce->steps($id, 'https://example.com'),
                $id . ' must yield at least one reproduce step'
            );
        }
    }
}
