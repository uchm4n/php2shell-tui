<?php

declare(strict_types=1);

namespace Php2ShellTui\Tests\Integration;

use PHPUnit\Framework\TestCase;
use Php2ShellTui\Application;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Yaml\Yaml;

final class ScanCommandTest extends TestCase
{
    /**
     * Directories and files to remove when the test ends.
     *
     * @var list<string>
     */
    private array $cleanup = [];

    private string $reportDir = '';

    protected function tearDown(): void
    {
        foreach ($this->cleanup as $path) {
            if (is_dir($path)) {
                self::removeDirectory($path);
            } elseif (is_file($path)) {
                unlink($path);
            }
        }

        $this->cleanup = [];
    }

    public function testItFailsWithExitCodeTwoWhenTheConfigIsMissing(): void
    {
        [$code, $output] = $this->runCommand([
            'command' => 'scan',
            '--config' => '/nonexistent/php2shell-tui.yaml',
            '--format' => 'json',
        ]);

        self::assertSame(2, $code);
        self::assertStringContainsString('php2shell-tui', $output);
    }

    public function testAnUnreachableHostAloneIsNotAFinding(): void
    {
        $config = $this->writeConfig([
            'targets' => ['http://127.0.0.1:1/unreachable'],
            'checks' => ['php_presence' => true],
        ]);

        [$code, $output] = $this->runCommand([
            'command' => 'scan',
            '--config' => $config,
            '--format' => 'json',
        ]);

        self::assertSame(0, $code, 'an unreachable host alone is not a finding');
        self::assertStringContainsString('unreachable', $output);
    }

    public function testItExitsWithOneAndFindsTheExposureOnALiveHost(): void
    {
        $port = self::findFreePort();
        $process = self::startServer($port);

        try {
            $config = $this->writeConfig([
                'targets' => ['http://127.0.0.1:' . $port . '/'],
                'checks' => [
                    'php_presence' => true,
                    'php_version' => true,
                    'sensitive_files' => true,
                ],
            ]);

            [$code] = $this->runCommand([
                'command' => 'scan',
                '--config' => $config,
                '--format' => 'json',
            ]);

            self::assertSame(1, $code, 'a critical finding must exit with 1');

            $decoded = json_decode((string) file_get_contents(self::latestReport()), true, 512, JSON_THROW_ON_ERROR);
            $severities = array_column($decoded['findings'], 'severity', 'id');

            self::assertSame('critical', $severities['php2shell-version'] ?? null);
            self::assertSame('high', $severities['sensitive-file-env'] ?? null);
        } finally {
            self::killServer($process, $port);
        }
    }

    public function testTheInjectionCheckDoesNotRunWithoutVerify(): void
    {
        [$port, $process] = $this->fixture();

        try {
            [$code, $output] = $this->runCommand([
                'command' => 'scan',
                '--config' => $this->injectionConfig($port),
                '--format' => 'json',
            ]);

            self::assertSame(0, $code);
            self::assertStringNotContainsString('sql_injection', $output);
        } finally {
            self::killServer($process, $port);
        }
    }

    public function testVerifyRunsTheInjectionCheckAndFindsTheSqlInjection(): void
    {
        [$port, $process] = $this->fixture();

        try {
            [$code, $output] = $this->runCommand([
                'command' => 'scan',
                '--config' => $this->injectionConfig($port),
                '--format' => 'json',
                '--verify' => true,
            ]);

            self::assertSame(1, $code);
            self::assertStringContainsString('sql_injection', $output);
        } finally {
            self::killServer($process, $port);
        }
    }


    /**
     * @return array{int, mixed}
     */
    private function fixture(): array
    {
        $port = self::findFreePort();

        return [$port, self::startServer($port)];
    }

    private function injectionConfig(int $port): string
    {
        return $this->writeConfig([
            'targets' => ['http://127.0.0.1:' . $port . '/search?q=test'],
            'checks' => ['injection' => true, 'php2shell' => false],
        ]);
    }

    private function php2shellConfig(int $port): string
    {
        return $this->writeConfig([
            'targets' => [[
                'url' => 'http://127.0.0.1:' . $port . '/',
                'post_path' => '/index.php',
                'poc_profile' => 'php-8.4.26-bookworm-amd64',
            ]],
            'checks' => ['php2shell' => true],
        ]);
    }

    private function php2shellGuessConfig(int $port): string
    {
        return $this->writeConfig([
            'targets' => [[
                'url' => 'http://127.0.0.1:' . $port . '/',
                'post_path' => '/index.php',
            ]],
            'checks' => ['php2shell' => true],
            'poc' => [
                'guess' => true,
                'arch' => 'amd64',
                'workers' => 2,
                'max_attempts' => 1,
                'total_timeout' => 10,
                'profiles' => ['php-8.4.26-apache-bookworm-amd64'],
            ],
        ]);
    }

    public function testThePhp2ShellGuessDoesNotRunWithoutVerify(): void
    {
        [$port, $process] = $this->fixture();

        try {
            [$code, $output] = $this->runCommand([
                'command' => 'scan',
                '--config' => $this->php2shellGuessConfig($port),
                '--format' => 'json',
            ]);

            self::assertNotSame(2, $code);
            self::assertStringNotContainsString('php2shell-rce', $output);
        } finally {
            self::killServer($process, $port);
        }
    }

    public function testThePhp2ShellDoesNotRunWithoutVerify(): void
    {
        [$port, $process] = $this->fixture();

        try {
            [$code, $output] = $this->runCommand([
                'command' => 'scan',
                '--config' => $this->php2shellConfig($port),
                '--format' => 'json',
            ]);

            self::assertNotSame(2, $code);
            self::assertStringNotContainsString('php2shell-rce', $output);
        } finally {
            self::killServer($process, $port);
        }
    }

    public function testThePhp2ShellVerifyWithoutWorkersSendsNoPayload(): void
    {
        [$port, $process] = $this->fixture();

        try {
            [$code, $output] = $this->runCommand([
                'command' => 'scan',
                '--config' => $this->php2shellConfig($port),
                '--format' => 'json',
                '--verify' => true,
            ]);

            self::assertNotSame(2, $code);
            self::assertStringContainsString('php2shell-poc-inconclusive', $output);
            self::assertStringContainsString('workers', $output);
            self::assertStringNotContainsString('php2shell-rce', $output);
        } finally {
            self::killServer($process, $port);
        }
    }

    public function testThePhp2ShellVerifyWithoutAProfileSendsNoPayload(): void
    {
        [$port, $process] = $this->fixture();

        try {
            $config = $this->writeConfig([
                'targets' => [[
                    'url' => 'http://127.0.0.1:' . $port . '/',
                    'post_path' => '/index.php',
                ]],
                'checks' => ['php2shell' => true],
            ]);

            [$code, $output] = $this->runCommand([
                'command' => 'scan',
                '--config' => $config,
                '--format' => 'json',
                '--verify' => true,
                '--php-version' => '7.4.33',
                '--workers' => '1',
            ]);

            self::assertNotSame(2, $code);
            self::assertStringContainsString('no calibrated profile', $output);
            self::assertStringNotContainsString('php2shell-rce', $output);
        } finally {
            self::killServer($process, $port);
        }
    }

    /**
     * @param array<string, mixed> $input
     * @return array{int, string}
     */
    private function runCommand(array $input): array
    {
        $application = new Application();
        $application->setAutoExit(false);
        $application->setCatchExceptions(false);
        $output = new BufferedOutput();

        $code = $application->run(new ArrayInput($input), $output);

        return [$code, $output->fetch()];
    }

    /**
     * @param array<string, mixed> $data
     */
    private function writeConfig(array $data): string
    {
        $dir = sys_get_temp_dir() . '/php2shell-tui-test-' . bin2hex(random_bytes(6));
        mkdir($dir, 0o755, true);
        $this->cleanup[] = $dir;

        $this->reportDir = $dir . '/reports';
        $data['output'] = ['report_dir' => $this->reportDir];

        $path = $dir . '/php2shell-tui.yaml';
        file_put_contents($path, Yaml::dump($data, 4));

        return $path;
    }

    private function latestReport(): string
    {
        $reports = glob($this->reportDir . '/php2shell-tui-*.json') ?: [];
        self::assertNotSame([], $reports, 'the command must write a report');

        return (string) end($reports);
    }

    private static function removeDirectory(string $dir): void
    {
        foreach (glob($dir . '/*') ?: [] as $path) {
            if (is_dir($path)) {
                self::removeDirectory($path);
            } else {
                unlink($path);
            }
        }

        rmdir($dir);
    }

    private static function findFreePort(): int
    {
        $socket = stream_socket_server('tcp://127.0.0.1:0', $errno, $errstr);
        $name = stream_socket_get_name($socket, false);
        fclose($socket);

        return (int) substr((string) $name, strrpos((string) $name, ':') + 1);
    }

    /**
     * @return resource
     */
    private static function startServer(int $port)
    {
        $process = proc_open(
            sprintf('exec php -S 127.0.0.1:%d %s', $port, escapeshellarg(__DIR__ . '/../Fixture/server.php')),
            [1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
            $pipes,
            null,
            // The built-in server is single threaded unless it forks workers.
            array_merge(getenv(), ['PHP_CLI_SERVER_WORKERS' => '8'])
        );

        self::waitForServer($port);

        return $process;
    }

    private static function waitForServer(int $port): void
    {
        $deadline = microtime(true) + 10.0;

        while (microtime(true) < $deadline) {
            $socket = @fsockopen('127.0.0.1', $port, $errno, $errstr, 0.2);
            if (is_resource($socket)) {
                fclose($socket);

                return;
            }

            usleep(50_000);
        }

        self::fail('The fixture server did not start.');
    }

    /**
     * @param resource $process
     */
    private static function killServer($process, int $port): void
    {
        // `php -S` ignores SIGTERM: neither the master nor its workers exit, so
        // the socket has to be taken away from whoever holds it.
        if (function_exists('exec')) {
            $pids = [];
            exec(sprintf('lsof -ti tcp:%d 2>/dev/null', $port), $pids);

            foreach ($pids as $pid) {
                $pid = (int) trim($pid);
                if ($pid > 1 && function_exists('posix_kill')) {
                    @posix_kill($pid, SIGKILL);
                }
            }
        }

        if (is_resource($process)) {
            proc_terminate($process, SIGKILL);
            proc_close($process);
        }
    }
}
