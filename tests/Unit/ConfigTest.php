<?php

declare(strict_types=1);

namespace Php2ShellTui\Tests\Unit;

use Php2ShellTui\Application;
use Php2ShellTui\Config;
use Php2ShellTui\Severity;
use PHPUnit\Framework\Attributes\DataProvider;
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
        self::assertSame(180, $config->pocTimeout);
        self::assertSame(150, $config->pocMaxWorkers);
    }

    public function testItParsesPocOptions(): void
    {
        $config = Config::fromArray([
            'targets' => ['https://example.com'],
            'options' => ['poc_timeout' => 240, 'poc_max_workers' => 50],
        ]);

        self::assertSame(240, $config->pocTimeout);
        self::assertSame(50, $config->pocMaxWorkers);
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
            ['php2shell', 'injection', 'sql_injection', 'reflected_xss', 'local_file_inclusion'],
            $config->enabledChecks(),
        );
    }

    public function testPhp2ShellIsEnabledByDefault(): void
    {
        $config = Config::fromArray(['targets' => ['https://example.com']]);

        self::assertTrue($config->checkEnabled('php2shell'));
    }

    public function testPhp2ShellCanBeDisabledExplicitly(): void
    {
        $config = Config::fromArray([
            'targets' => ['https://example.com'],
            'checks' => ['php2shell' => false],
        ]);

        self::assertFalse($config->checkEnabled('php2shell'));
    }

    public function testItParsesThePhp2ShellTargetOptions(): void
    {
        $config = Config::fromArray([
            'targets' => [[
                'url' => 'https://app.example/',
                'post_path' => '/index.php',
                'poc_profile' => 'php-8.4.26-apache-amd64',
            ]],
        ]);

        $target = $config->targets[0];
        self::assertSame('/index.php', $target->postPath);
        self::assertSame('php-8.4.26-apache-amd64', $target->pocProfile);
    }

    public function testItRejectsACrossOriginPostPath(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('post_path');
        Config::fromArray([
            'targets' => [[
                'url' => 'https://app.example/',
                'post_path' => 'https://evil.example/index.php',
            ]],
        ]);
    }

    public function testItRejectsARelativePostPath(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('post_path');
        Config::fromArray([
            'targets' => [[
                'url' => 'https://app.example/',
                'post_path' => 'index.php',
            ]],
        ]);
    }

    public function testItRejectsARemotePocProfile(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('poc_profile');
        Config::fromArray([
            'targets' => [[
                'url' => 'https://app.example/',
                'poc_profile' => 'https://evil.example/profile.json',
            ]],
        ]);
    }

    public static function nonBooleanValues(): array
    {
        return [['false'], ['no'], ['off'], [1], [0]];
    }

    #[DataProvider('nonBooleanValues')]
    public function testItRejectsNonBooleanCheckToggles(mixed $value): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('boolean');
        Config::fromArray([
            'targets' => ['https://example.com'],
            'checks' => ['php2shell' => $value],
        ]);
    }

    public function testItRejectsAStringStagingFlag(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('staging');
        Config::fromArray([
            'targets' => [[
                'url' => 'https://lab.example/',
                'staging' => 'false',
            ]],
        ]);
    }

    public function testItRejectsControlCharactersInHeadersAndPaths(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Config::fromArray([
            'targets' => [[
                'url' => 'https://app.example/',
                'vhost' => "app.example\r\nX-Test: y",
            ]],
        ]);
    }

    public function testItRejectsControlCharactersInPostPaths(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Config::fromArray([
            'targets' => [[
                'url' => 'https://app.example/',
                'post_path' => "/index.php\r\nX-Test: y",
            ]],
        ]);
    }

    public function testItLoadsTheShippedExampleConfig(): void
    {
        $config = Config::fromFile(dirname(__DIR__, 2) . '/php2shell-tui.yaml');

        self::assertCount(2, $config->targets);
        self::assertSame('https://lamart.ge/', $config->targets[0]->url);
        self::assertSame(['/admin'], $config->targets[0]->paths);
        self::assertTrue($config->targets[0]->staging);
        self::assertSame('https://nuc.ge', $config->targets[1]->url);
        self::assertSame(['/admin', '/wp-admin', '/login'], $config->targets[1]->paths);
    }

    public function testItRejectsAMissingConfigFile(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        Config::fromFile(dirname(__DIR__, 2) . '/no-such-config.yaml');
    }
}
