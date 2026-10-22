<?php

declare(strict_types=1);

namespace Php2ShellTui\Tests\Unit;

use Php2ShellTui\Application;
use Php2ShellTui\Config;
use Php2ShellTui\Severity;
use PHPUnit\Framework\TestCase;

final class ConfigTest extends TestCase
{
    public function testItLoadsAValidConfig(): void
    {
        $config = Config::fromArray([
            'targets' => [
                'https://www.php2shell.com',
                ['url' => 'https://legacy.example.com', 'vhost' => 'legacy.example.com', 'paths' => ['/wp-content/uploads']],
            ],
            'checks' => ['php_version' => true, 'tls' => false],
            'options' => ['concurrency' => 4, 'min_severity' => 'high'],
            'output' => ['format' => 'json'],
        ]);

        self::assertCount(2, $config->targets);
        self::assertSame('www.php2shell.com', $config->targets[0]->host());
        self::assertSame('legacy.example.com', $config->targets[1]->vhost);
        self::assertSame(['/wp-content/uploads'], $config->targets[1]->paths);
        self::assertSame(4, $config->concurrency);
        self::assertSame(Severity::High, $config->minSeverity);
        self::assertSame('json', $config->format);
        self::assertTrue($config->checkEnabled('php_version'));
        self::assertFalse($config->checkEnabled('tls'));
    }

    public function testItRejectsAnEmptyTargetList(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('targets');
        Config::fromArray(['targets' => []]);
    }

    public function testItRejectsAMalformedUrl(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Config::fromArray(['targets' => ['not a url']]);
    }

    public function testItRejectsAnUnknownCheckName(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('unknown check');
        Config::fromArray([
            'targets' => ['https://example.com'],
            'checks' => ['no_such_check' => true],
        ]);
    }

    public function testItRejectsAnUnknownOutputFormat(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Config::fromArray([
            'targets' => ['https://example.com'],
            'output' => ['format' => 'pdf'],
        ]);
    }

    public function testDefaultsAreApplied(): void
    {
        $config = Config::fromArray(['targets' => ['https://example.com']]);

        self::assertSame(8, $config->concurrency);
        self::assertSame(10, $config->timeout);
        self::assertSame(5, $config->connectTimeout);
        self::assertSame(100, $config->delayMs);
        self::assertSame(Severity::Medium, $config->minSeverity);
        self::assertSame('tui', $config->format);
        self::assertSame('./reports', $config->reportDir);
    }

    public function testTheDefaultUserAgentNamesTheApplicationVersion(): void
    {
        $config = Config::fromArray(['targets' => ['https://example.com']]);

        self::assertStringContainsString(Application::VERSION, $config->userAgent);
    }

    public function testATargetCanOverrideTheHostHeader(): void
    {
        $config = Config::fromArray([
            'targets' => [
                'https://www.php2shell.com',
                ['url' => 'https://203.0.113.10', 'vhost' => 'legacy.example.com'],
            ],
        ]);

        self::assertSame([], $config->targets[0]->requestHeaders());
        self::assertSame('www.php2shell.com', $config->targets[0]->label());
        self::assertSame(['Host' => 'legacy.example.com'], $config->targets[1]->requestHeaders());
        self::assertSame('legacy.example.com', $config->targets[1]->label());
    }

    public function testTheInjectionToggleEnablesTheThreeVerificationChecks(): void
    {
        $config = Config::fromArray([
            'targets' => ['https://example.com'],
            'checks' => ['injection' => true],
        ]);

        self::assertTrue($config->checkEnabled('sql_injection'));
        self::assertTrue($config->checkEnabled('reflected_xss'));
        self::assertTrue($config->checkEnabled('local_file_inclusion'));
        self::assertSame(
            ['injection', 'sql_injection', 'reflected_xss', 'local_file_inclusion'],
            $config->enabledChecks(),
        );
    }

    public function testItLoadsTheShippedExampleConfig(): void
    {
        $config = Config::fromFile(dirname(__DIR__, 2) . '/php2shell-tui.yaml');

        self::assertCount(5, $config->targets);
        self::assertSame('https://example1.com', $config->targets[0]->url);
        self::assertSame('https://legacy.example4.com', $config->targets[3]->url);
        self::assertSame(['/wp-content/uploads'], $config->targets[3]->paths);
        self::assertTrue($config->targets[3]->staging);
        self::assertSame(['/admin', '/wp-admin', '/login'], $config->targets[4]->paths);
    }

    public function testItRejectsAMissingConfigFile(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Config::fromFile(dirname(__DIR__, 2) . '/no-such-config.yaml');
    }
}
