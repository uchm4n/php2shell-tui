<?php

declare(strict_types=1);

namespace Php2ShellTui\Command;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\CurlMultiHandler;
use GuzzleHttp\HandlerStack;
use Php2ShellTui\Check\AppFingerprint;
use Php2ShellTui\Check\LocalFileInclusion;
use Php2ShellTui\Check\OpenPorts;
use Php2ShellTui\Check\Php2Shell;
use Php2ShellTui\Check\PhpDetection;
use Php2ShellTui\Check\PhpVersion;
use Php2ShellTui\Check\ReflectedXss;
use Php2ShellTui\Check\Registry;
use Php2ShellTui\Check\SecurityHeaders;
use Php2ShellTui\Check\SensitiveFiles;
use Php2ShellTui\Check\SqlInjection;
use Php2ShellTui\Check\Tls;
use Php2ShellTui\Check\WebshellIndicators;
use Php2ShellTui\Config;
use Php2ShellTui\Data\Reproduce;
use Php2ShellTui\Data\Wordlists;
use Php2ShellTui\Engine;
use Php2ShellTui\Http\Client;
use Php2ShellTui\Http\Pool;
use Php2ShellTui\PhpVersionDb;
use Php2ShellTui\Poc\GuessPlan;
use Php2ShellTui\Poc\Php2ShellPoc;
use Php2ShellTui\Report\Report;
use Php2ShellTui\ScanCancelled;
use Php2ShellTui\ScanRestart;
use Php2ShellTui\ScanResult;
use Php2ShellTui\Ui\PlainRenderer;
use Php2ShellTui\Ui\TuiRenderer;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'scan', description: 'Scan the configured hosts for security exposure')]
final class ScanCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->addOption('config', 'c', InputOption::VALUE_REQUIRED, 'Path to the configuration file', 'php2shell-tui.yaml')
            ->addOption('format', 'f', InputOption::VALUE_REQUIRED, 'Output format: tui, text, json, markdown', '')
            ->addOption('no-tui', null, InputOption::VALUE_NONE, 'Never use the interactive interface')
            ->addOption('verify', null, InputOption::VALUE_NONE, 'Run the proof-of-concept requests (explicit authorization)')
            ->addOption('yes', 'y', InputOption::VALUE_NONE, 'Deprecated; accepted for compatibility (--verify is the confirmation)')
            ->addOption('output-dir', null, InputOption::VALUE_REQUIRED, 'Directory for the written report');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        try {
            $config = Config::fromFile((string) $input->getOption('config'));

            $format = (string) $input->getOption('format');
            if ($format === '') {
                $isTty = \defined('STDOUT') && stream_isatty(STDOUT);
                $format = ($input->getOption('no-tui') || !$isTty) ? 'text' : $config->format;
            }

            if (!in_array($format, Config::FORMATS, true)) {
                throw new \InvalidArgumentException(sprintf(
                    'Unknown output format "%s"; expected one of %s.',
                    $format,
                    implode(', ', Config::FORMATS)
                ));
            }

            $verify = (bool) $input->getOption('verify');

            $root = dirname(__DIR__, 2);
            $dataDir = $root . '/src/Data';

            $handler = new CurlMultiHandler([
                'max_total_connections' => $config->concurrency,
                'max_host_connections' => 2,
            ]);
            $client = new Client(new GuzzleClient([
                'handler' => HandlerStack::create($handler),
                'http_errors' => false,
                'timeout' => $config->timeout,
                'connect_timeout' => $config->connectTimeout,
                'headers' => ['User-Agent' => $config->userAgent],
            ]), $config->delayMs);
            $pool = new Pool($handler, $client);

            $wordlists = new Wordlists($dataDir);
            $reproduce = new Reproduce($dataDir . '/repro');
            $db = PhpVersionDb::fromFile($dataDir . '/php-affected.json');

            $guess = $config->pocGuess
                ? new GuessPlan(
                    profiles: $config->pocProfiles,
                    arch: $config->pocArch,
                    workers: $config->pocWorkers,
                    maxAttempts: $config->pocMaxAttempts,
                    totalTimeout: $config->pocTotalTimeout,
                )
                : null;

            $checks = [
                'php_presence' => new PhpDetection($reproduce),
                'php_version' => new PhpVersion($db, $reproduce),
                'php2shell' => new Php2Shell(
                    $reproduce,
                    $verify,
                    $db,
                    new Php2ShellPoc(
                        client: $client,
                        timeout: $config->pocTimeout,
                        maxWorkers: $config->pocMaxWorkers,
                    ),
                    $dataDir . '/poc',
                    $guess,
                    $client,
                    workers: $config->pocWorkers,
                ),
                'sensitive_files' => new SensitiveFiles($wordlists, $reproduce),
                'security_headers' => new SecurityHeaders($reproduce),
                'tls' => new Tls($reproduce),
                'app_fingerprint' => new AppFingerprint($reproduce),
                'webshell_indicators' => new WebshellIndicators($wordlists, $reproduce),
                'open_ports' => new OpenPorts($wordlists, $reproduce, client: $client),
            ];

            if ($verify && $config->checkEnabled('injection')) {
                $checks['sql_injection'] = new SqlInjection($reproduce, $client);
                $checks['reflected_xss'] = new ReflectedXss($reproduce, $client);
                $checks['local_file_inclusion'] = new LocalFileInclusion($reproduce, $client);
            }

            $registry = new Registry($checks);

            $engine = new Engine($pool, $registry);

            if ($format === 'tui') {
                $renderer = new TuiRenderer();
                $targets = array_map(static fn ($t): string => $t->label(), $config->targets);
                $result = null;
                $path = null;
                $error = null;
                $cancelled = false;

                try {
                    $renderer->start($targets);
                    $renderer->draw();

                    while (true) {
                        $restart = false;

                        try {
                            $result = $engine->run(
                                $config,
                                static function (string $label, string $phase, int $done, int $total) use ($renderer): void {
                                    if ($phase === 'verify') {
                                        $renderer->setVerify($label, $done, $total);
                                    } else {
                                        $renderer->update($label, $phase, $done, $total);
                                    }

                                    $renderer->pollKeys();
                                    $renderer->draw();
                                },
                                static function () use ($renderer): void {
                                    $renderer->tick();

                                    if ($renderer->isRestartRequested()) {
                                        throw new ScanRestart();
                                    }

                                    if ($renderer->isQuitRequested()) {
                                        throw new ScanCancelled();
                                    }
                                },
                            );

                            $renderer->setFindings($result->findings);
                            $renderer->finish(
                                array_column($result->unreachable, 'target'),
                                array_column($result->unscannable, 'target'),
                                $result->duration,
                            );

                            $report = new Report($result, $config);
                            $rendered = $report->render($format);
                            $path = $this->writeReport($report, $format, $rendered, $input, $config);

                            // Stay here until the operator quits or restarts, so
                            // the results are read inside the TUI instead of being
                            // dumped to the shell.
                            $renderer->waitForQuit();
                        } catch (ScanRestart) {
                            $restart = true;
                        } catch (ScanCancelled) {
                            $cancelled = true;
                            break;
                        } catch (\Throwable $e) {
                            try {
                                $renderer->fail($e);
                                $renderer->waitForQuit();
                            } catch (\Throwable) {
                                // The renderer itself is unusable; let the outer
                                // handler restore the terminal and print the
                                // original failure.
                                throw $e;
                            }

                            if (!$renderer->isRestartRequested()) {
                                $error = $e;
                                break;
                            }

                            $restart = true;
                        }

                        if ($renderer->isRestartRequested()) {
                            $restart = true;
                        }

                        if (!$restart) {
                            break;
                        }

                        $renderer->restart($targets);
                    }
                } finally {
                    $renderer->stop();
                }

                if ($cancelled) {
                    $this->note($output, 'Scan cancelled.');

                    return 130;
                }

                if ($error !== null) {
                    $this->note($output, 'Scan failed: ' . $error->getMessage());

                    return 2;
                }

                if ($result === null) {
                    $this->note($output, 'Scan did not complete.');

                    return 2;
                }

                $this->note($output, sprintf('Report written to %s', (string) $path));

                return $this->exitCode($result, $config);
            }

            $result = $engine->run($config);
            $report = new Report($result, $config);
            $rendered = $report->render($format);

            (new PlainRenderer())->render($rendered, $output);

            $path = $this->writeReport($report, $format, $rendered, $input, $config);
            $this->note($output, sprintf('Report written to %s', $path));

            return $this->exitCode($result, $config);
        } catch (\Throwable $e) {
            $output->writeln('<error>' . $e->getMessage() . '</error>');

            return 2;
        }
    }

    private function writeReport(
        Report $report,
        string $format,
        string $rendered,
        InputInterface $input,
        Config $config
    ): string {
        $directory = (string) ($input->getOption('output-dir') ?: $config->reportDir);
        if (!is_dir($directory) && !@mkdir($directory, 0o755, true) && !is_dir($directory)) {
            throw new \RuntimeException(sprintf('Cannot create the report directory "%s".', $directory));
        }

        $path = rtrim($directory, '/') . '/' . $report->filename($format);
        if (file_put_contents($path, $rendered) === false) {
            throw new \RuntimeException(sprintf('Cannot write the report to "%s".', $path));
        }

        return $path;
    }

    private function exitCode(ScanResult $result, Config $config): int
    {
        foreach ($result->findings as $finding) {
            if ($finding->severity->atLeast($config->minSeverity)) {
                return 1;
            }
        }

        return 0;
    }

    /**
     * The note goes to the error stream when the output has one, so that
     * stdout stays machine-readable for the json format.
     */
    private function note(OutputInterface $output, string $message): void
    {
        $stream = $output instanceof ConsoleOutputInterface ? $output->getErrorOutput() : $output;
        $stream->writeln($message);
    }
}
