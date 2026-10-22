<?php

declare(strict_types=1);

namespace Php2Scan\Command;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\CurlMultiHandler;
use GuzzleHttp\HandlerStack;
use Php2Scan\Check\AppFingerprint;
use Php2Scan\Check\LocalFileInclusion;
use Php2Scan\Check\OpenPorts;
use Php2Scan\Check\PhpDetection;
use Php2Scan\Check\PhpVersion;
use Php2Scan\Check\ReflectedXss;
use Php2Scan\Check\Registry;
use Php2Scan\Check\SecurityHeaders;
use Php2Scan\Check\SensitiveFiles;
use Php2Scan\Check\SqlInjection;
use Php2Scan\Check\Tls;
use Php2Scan\Check\WebshellIndicators;
use Php2Scan\Config;
use Php2Scan\Data\Reproduce;
use Php2Scan\Data\Wordlists;
use Php2Scan\Engine;
use Php2Scan\Http\Client;
use Php2Scan\Http\Pool;
use Php2Scan\PhpVersionDb;
use Php2Scan\Report\Report;
use Php2Scan\Ui\PlainRenderer;
use Php2Scan\Ui\TuiRenderer;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Question\ConfirmationQuestion;

#[AsCommand(name: 'scan', description: 'Scan the configured hosts for security exposure')]
final class ScanCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->addOption('config', 'c', InputOption::VALUE_REQUIRED, 'Path to the configuration file', 'php2scan.yaml')
            ->addOption('format', 'f', InputOption::VALUE_REQUIRED, 'Output format: tui, text, json, markdown', '')
            ->addOption('no-tui', null, InputOption::VALUE_NONE, 'Never use the interactive interface')
            ->addOption('verify', null, InputOption::VALUE_NONE, 'Run the proof-of-concept requests')
            ->addOption('yes', 'y', InputOption::VALUE_NONE, 'Do not ask for confirmation')
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
            $dataDir = $root . '/data';

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

            $checks = [
                'php_presence' => new PhpDetection($reproduce),
                'php_version' => new PhpVersion($db, $reproduce),
                'sensitive_files' => new SensitiveFiles($wordlists, $reproduce),
                'security_headers' => new SecurityHeaders($reproduce),
                'tls' => new Tls($reproduce),
                'app_fingerprint' => new AppFingerprint($reproduce),
                'webshell_indicators' => new WebshellIndicators($wordlists, $reproduce),
                'open_ports' => new OpenPorts($wordlists, $reproduce),
            ];

            if ($verify && $config->checkEnabled('injection')) {
                $checks['sql_injection'] = new SqlInjection($reproduce, $client);
                $checks['reflected_xss'] = new ReflectedXss($reproduce, $client);
                $checks['local_file_inclusion'] = new LocalFileInclusion($reproduce, $client);
            }

            $registry = new Registry($checks);

            $engine = new Engine($pool, $registry);

            if ($verify && !$input->getOption('yes')) {
                $needsConfirmation = false;
                foreach ($config->targets as $target) {
                    if (!$target->staging) {
                        $needsConfirmation = true;
                        break;
                    }
                }

                if ($needsConfirmation) {
                    $confirmed = $this->getHelper('question')->ask(
                        $input,
                        $output,
                        new ConfirmationQuestion(
                            'Verification sends proof-of-concept requests to hosts that are not marked as staging. Continue? [y/N] ',
                            false
                        )
                    );

                    if (!$confirmed) {
                        $output->writeln('<comment>Aborted - verification requires --yes to skip this prompt.</comment>');

                        return 2;
                    }
                }
            }

            if ($format === 'tui') {
                $renderer = new TuiRenderer();
                $renderer->start(array_map(static fn ($t): string => $t->label(), $config->targets));

                try {
                    $result = $engine->run($config, static function (string $label, string $phase, int $done, int $total) use ($renderer): void {
                        $renderer->update($label, $phase, $done, $total);
                        $renderer->pollKeys();
                        $renderer->draw();
                    });

                    $renderer->setFindings($result->findings);
                    $renderer->draw();
                } finally {
                    // Puts the terminal back before the plain report is written,
                    // including when the scan throws or the user quits.
                    $renderer->stop();
                }
            } else {
                $result = $engine->run($config);
            }

            $report = new Report($result, $config);
            $rendered = $report->render($format);

            (new PlainRenderer())->render($rendered, $output);

            $directory = (string) ($input->getOption('output-dir') ?: $config->reportDir);
            if (!is_dir($directory) && !@mkdir($directory, 0o755, true) && !is_dir($directory)) {
                throw new \RuntimeException(sprintf('Cannot create the report directory "%s".', $directory));
            }

            $path = rtrim($directory, '/') . '/' . $report->filename($format);
            if (file_put_contents($path, $rendered) === false) {
                throw new \RuntimeException(sprintf('Cannot write the report to "%s".', $path));
            }

            $this->note($output, sprintf('Report written to %s', $path));

            $hasFindings = false;
            foreach ($result->findings as $finding) {
                if ($finding->severity->atLeast($config->minSeverity)) {
                    $hasFindings = true;
                    break;
                }
            }

            return $hasFindings ? 1 : 0;
        } catch (\Throwable $e) {
            $output->writeln('<error>' . $e->getMessage() . '</error>');

            return 2;
        }
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
