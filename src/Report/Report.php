<?php

declare(strict_types=1);

namespace Php2ShellTui\Report;

use Php2ShellTui\Config;
use Php2ShellTui\Finding;
use Php2ShellTui\ScanResult;
use Php2ShellTui\Severity;

final class Report
{
    public function __construct(
        private readonly ScanResult $result,
        private readonly Config $config,
    ) {
    }

    public function render(string $format): string
    {
        return match ($format) {
            'json' => $this->json(),
            'markdown' => $this->markdown(),
            default => $this->text(),
        };
    }

    public function filename(string $format, ?\DateTimeImmutable $now = null): string
    {
        $now ??= new \DateTimeImmutable();
        $extension = match ($format) {
            'json' => 'json',
            'markdown' => 'md',
            default => 'txt',
        };

        return sprintf('php2shell-tui-%s.%s', $now->format('Ymd-His'), $extension);
    }

    /**
     * Findings below min_severity are shown in the TUI and in the JSON output,
     * but are left out of the text and markdown reports (spec §18.2).
     *
     * @return list<Finding>
     */
    private function reportable(): array
    {
        return array_values(array_filter(
            $this->result->findings,
            fn (Finding $f): bool => $f->severity->atLeast($this->config->minSeverity)
        ));
    }

    public function text(): string
    {
        $lines = [];
        $lines[] = sprintf('php2shell-tui report — %s', (new \DateTimeImmutable())->format('Y-m-d H:i:s'));
        $lines[] = '';

        $reportable = $this->reportable();

        if ($reportable === []) {
            $lines[] = 'No findings.';
        }

        foreach ($reportable as $finding) {
            foreach ($this->block($finding) as $line) {
                $lines[] = $line;
            }
            $lines[] = '';
        }

        foreach ($this->result->unreachable as $target) {
            $lines[] = sprintf('! UNREACHABLE  %s — %s', $target['target'], $target['error']);
            $lines[] = '';
        }

        foreach ($this->result->unscannable as $target) {
            $lines[] = sprintf('! BLOCKED  %s — HTTP %d', $target['target'], $target['status']);
            $lines[] = '';
        }

        $lines[] = sprintf(
            '%d finding(s) at or above %s, %d unreachable, %d unscannable in %.1fs',
            count($reportable),
            $this->config->minSeverity->value,
            count($this->result->unreachable),
            count($this->result->unscannable),
            $this->result->duration
        );

        return implode("\n", $lines) . "\n";
    }

    public function json(): string
    {
        $summary = [];
        foreach (Severity::cases() as $severity) {
            $summary[$severity->value] = 0;
        }
        foreach ($this->result->findings as $finding) {
            $summary[$finding->severity->value]++;
        }

        $payload = [
            'generated_at' => (new \DateTimeImmutable())->format(DATE_ATOM),
            'duration' => $this->result->duration,
            'summary' => $summary,
            'targets' => array_map(
                static fn ($target): array => ['url' => $target->url, 'label' => $target->label()],
                $this->config->targets
            ),
            'findings' => array_map(static fn (Finding $f): array => [
                'id' => $f->id,
                'title' => $f->title,
                'severity' => $f->severity->value,
                'target' => $f->target,
                'evidence' => $f->evidence,
                'exploit' => $f->exploit,
                'reproduce' => $f->reproduce,
            ], $this->result->findings),
            'unreachable' => $this->result->unreachable,
            'unscannable' => $this->result->unscannable,
        ];

        return json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
    }

    public function markdown(): string
    {
        $lines = [];
        $lines[] = '# php2shell-tui report';
        $lines[] = '';
        $lines[] = sprintf('Generated %s.', (new \DateTimeImmutable())->format('Y-m-d H:i:s'));
        $lines[] = '';

        foreach ($this->reportable() as $finding) {
            $lines[] = sprintf('## %s · %s', Theme::label($finding->severity), $finding->title);
            $lines[] = '';
            $lines[] = sprintf('- **Target:** %s', $finding->target);
            $lines[] = sprintf('- **Evidence:** %s', $finding->evidence);
            $lines[] = sprintf('- **How to exploit:** %s', $finding->exploit);
            $lines[] = '';
            $lines[] = '```bash';
            foreach ($finding->reproduce as $step) {
                $lines[] = $step;
            }
            $lines[] = '```';
            $lines[] = '';
        }

        return implode("\n", $lines) . "\n";
    }

    /**
     * @return list<string>
     */
    private function block(Finding $finding): array
    {
        $lines = [];
        $lines[] = sprintf(
            '%s %s  %s — %s',
            Theme::symbol($finding->severity),
            str_pad(Theme::label($finding->severity), 8),
            $finding->title,
            $finding->target
        );
        $lines[] = '    ' . $finding->evidence;
        $lines[] = '    How to exploit: ' . $finding->exploit;

        if ($finding->id === 'php2shell-version' && $finding->severity === Severity::Critical) {
            $lines[] = '    Fix: upgrade PHP to the first fixed release for its branch and restart the Apache/FPM workers.';
            $lines[] = '    Note: a vendor backport may carry the fix without a version change - check the package revision before assuming the host is still exposed.';
        }

        foreach ($finding->reproduce as $step) {
            foreach (preg_split('/\R/', $step) ?: [] as $line) {
                $lines[] = '    $ ' . $line;
            }
        }

        return $lines;
    }
}
