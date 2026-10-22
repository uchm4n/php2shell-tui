<?php

declare(strict_types=1);

namespace Php2ShellTui\Tests\Unit;

use PHPUnit\Framework\TestCase;

final class SmokeTest extends TestCase
{
    public function testTheConsoleApplicationRunsAndReportsItsVersion(): void
    {
        $application = new \Php2ShellTui\Application();
        $application->setAutoExit(false);
        $application->setCatchExceptions(false);

        $output = new \Symfony\Component\Console\Output\BufferedOutput();
        $code = $application->run(new \Symfony\Component\Console\Input\ArrayInput(['--version' => true]), $output);

        self::assertSame(0, $code);
        self::assertStringContainsString('php2shell-tui', $output->fetch());
    }

    public function testTheShippedExampleConfigParses(): void
    {
        $path = dirname(__DIR__, 2) . '/php2shell-tui.yaml';
        $config = (new \Symfony\Component\Yaml\Yaml())->parseFile($path);

        self::assertIsArray($config);
        self::assertCount(5, $config['targets']);
        self::assertSame('https://example1.com', $config['targets'][0]);
        self::assertSame('https://legacy.example5.com', $config['targets'][4]['url']);
        self::assertSame(['/admin', '/wp-admin', '/login'], $config['targets'][4]['paths']);
    }
}
