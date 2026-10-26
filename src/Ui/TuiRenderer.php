<?php

declare(strict_types=1);

namespace Php2ShellTui\Ui;

use Php2ShellTui\Finding;
use Php2ShellTui\Report\Theme;
use Php2ShellTui\Severity;
use PhpTui\Tui\Bridge\PhpTerm\PhpTermBackend;
use PhpTui\Tui\Color\AnsiColor;
use PhpTui\Tui\Display\Backend;
use PhpTui\Tui\Display\Display;
use PhpTui\Tui\DisplayBuilder;
use PhpTui\Tui\Extension\Core\Widget\BlockWidget;
use PhpTui\Tui\Extension\Core\Widget\GaugeWidget;
use PhpTui\Tui\Extension\Core\Widget\GridWidget;
use PhpTui\Tui\Extension\Core\Widget\Paragraph\Wrap;
use PhpTui\Tui\Extension\Core\Widget\ParagraphWidget;
use PhpTui\Tui\Extension\Core\Widget\Table\TableCell;
use PhpTui\Tui\Extension\Core\Widget\Table\TableRow;
use PhpTui\Tui\Extension\Core\Widget\TableWidget;
use PhpTui\Tui\Layout\Constraint;
use PhpTui\Tui\Style\Modifier;
use PhpTui\Tui\Style\Style;
use PhpTui\Tui\Text\Line;
use PhpTui\Tui\Text\Span;
use PhpTui\Tui\Text\Title;
use PhpTui\Tui\Widget\Borders;
use PhpTui\Tui\Widget\BorderType;
use PhpTui\Tui\Widget\Direction;
use PhpTui\Term\Actions;
use PhpTui\Term\Event\CharKeyEvent;
use PhpTui\Term\Event\CodedKeyEvent;
use PhpTui\Term\EventProvider;
use PhpTui\Term\KeyCode;
use PhpTui\Term\KeyModifiers;
use PhpTui\Term\Terminal;

/**
 * The live view: progress and a colored findings pane.
 *
 * The renderer never runs a loop of its own during the scan. The scan drives
 * it, and the caller redraws the frame from the progress callback. Once the
 * scan ends, the caller keeps the renderer alive with waitForQuit().
 */
final class TuiRenderer
{
    private const MIN_PROGRESS_HEIGHT = 6;
    private const MAX_PROGRESS_HEIGHT = 12;

    /**
     * @var list<string> $targets
     */
    private array $targets = [];

    /**
     * @var array<string, string> $phases
     */
    private array $phases = [];

    /**
     * @var list<Finding> $findings
     */
    private array $findings = [];

    private int $selected = 0;
    private bool $expanded = false;
    private bool $quit = false;
    private bool $restart = false;
    private bool $complete = false;
    private bool $stopped = false;
    private ?int $done = null;
    private ?int $total = null;
    private int $unreachableCount = 0;
    private int $unscannableCount = 0;
    private float $duration = 0.0;
    private float $lastDraw = 0.0;
    private ?string $error = null;

    /**
     * @var array<string, array{done: int, total: int, started: float}>
     */
    private array $verify = [];

    private Display $display;
    private ?Terminal $terminal = null;
    private ?EventProvider $events = null;

    /**
     * The event source is injectable so key handling can be tested without a
     * terminal; the real one reads the terminal created above.
     */
    public function __construct(?Backend $backend = null, ?EventProvider $events = null)
    {
        if ($backend === null) {
            $this->terminal = Terminal::new();
            $backend = PhpTermBackend::new($this->terminal);
        }

        $this->events = $events ?? $this->terminal?->events();
        $this->display = DisplayBuilder::default($backend)->build();
    }

    /**
     * @param list<string> $targets
     */
    public function start(array $targets): void
    {
        $this->resetState($targets);

        if ($this->terminal === null) {
            return;
        }

        $this->terminal->queue(Actions::alternateScreenEnable(), Actions::cursorHide());
        $this->terminal->flush();
        $this->terminal->enableRawMode();
    }

    /**
     * Resets the view for another scan without re-entering the alternate
     * screen or raw mode.
     *
     * @param list<string> $targets
     */
    public function restart(array $targets): void
    {
        $this->resetState($targets);
        $this->draw();
    }

    /**
     * @param list<string> $targets
     */
    private function resetState(array $targets): void
    {
        $this->targets = $targets;
        $this->phases = array_fill_keys($targets, 'pending');
        $this->findings = [];
        $this->selected = 0;
        $this->expanded = false;
        $this->quit = false;
        $this->restart = false;
        $this->complete = false;
        $this->stopped = false;
        $this->done = null;
        $this->total = null;
        $this->unreachableCount = 0;
        $this->unscannableCount = 0;
        $this->duration = 0.0;
        $this->lastDraw = 0.0;
        $this->error = null;
        $this->verify = [];
    }

    public function update(string $targetLabel, string $phase, ?int $done = null, ?int $total = null): void
    {
        $this->phases[$targetLabel] = $phase;
        $this->done = $done ?? $this->done;
        $this->total = $total ?? $this->total;

        if ($phase !== 'verify') {
            unset($this->verify[$targetLabel]);
        }
    }

    /**
     * Shows the active verification attempt without resetting the request gauge.
     */
    public function setVerify(string $targetLabel, int $done, int $total): void
    {
        $started = $this->verify[$targetLabel]['started'] ?? microtime(true);

        $this->phases[$targetLabel] = 'verify';
        $this->verify[$targetLabel] = [
            'done' => max(0, $done),
            'total' => max(1, $total),
            'started' => $started,
        ];
    }

    /**
     * @param list<Finding> $findings
     */
    public function setFindings(array $findings): void
    {
        usort(
            $findings,
            static fn (Finding $a, Finding $b): int => $b->severity->rank() <=> $a->severity->rank()
        );

        $this->findings = $findings;
        $this->selected = 0;
        $this->expanded = false;
    }

    /**
     * Marks the scan as complete and records the final target states.
     *
     * @param list<string> $unreachable
     * @param list<string> $unscannable
     */
    public function finish(array $unreachable = [], array $unscannable = [], float $duration = 0.0): void
    {
        $this->complete = true;
        $this->duration = $duration;
        $this->unreachableCount = count($unreachable);
        $this->unscannableCount = count($unscannable);
        $this->verify = [];

        foreach ($this->targets as $target) {
            $this->phases[$target] = 'done';
        }

        foreach ($unreachable as $target) {
            $this->phases[$target] = 'unreachable';
        }

        foreach ($unscannable as $target) {
            $this->phases[$target] = 'blocked';
        }
    }

    /**
     * Keeps an in-session failure on screen instead of tearing the TUI down.
     */
    public function fail(\Throwable $error): void
    {
        $this->error = $error->getMessage() !== '' ? $error->getMessage() : $error::class;
    }

    public function selected(): ?Finding
    {
        return $this->findings[$this->selected] ?? null;
    }

    public function move(int $delta): void
    {
        if ($this->findings === []) {
            return;
        }

        $count = count($this->findings);
        $this->selected = (($this->selected + $delta) % $count + $count) % $count;
    }

    public function toggleExpanded(): void
    {
        $this->expanded = !$this->expanded;
    }

    public function isQuitRequested(): bool
    {
        return $this->quit;
    }

    public function isRestartRequested(): bool
    {
        return $this->restart;
    }

    public function requestQuit(): void
    {
        $this->quit = true;
    }

    public function requestRestart(): void
    {
        $this->restart = true;
        $this->quit = true;
    }

    public function handleKey(string $key): void
    {
        match ($key) {
            'q' => $this->quit = true,
            'r' => $this->requestRestart(),
            'j' => $this->move(1),
            'k' => $this->move(-1),
            "\n" => $this->toggleExpanded(),
            default => null,
        };
    }

    /**
     * Drains the pending terminal events.
     *
     * Returns true when at least one event was handled, so the caller can
     * redraw only when the frame actually changed.
     */
    public function pollKeys(): bool
    {
        if ($this->events === null) {
            return false;
        }

        $handled = false;

        while (($event = $this->events->next()) !== null) {
            $handled = true;

            if ($event instanceof CharKeyEvent) {
                if (($event->modifiers & KeyModifiers::CONTROL) !== 0 && $event->char === 'c') {
                    $this->quit = true;
                    continue;
                }

                $this->handleKey($event->char);
                continue;
            }

            if ($event instanceof CodedKeyEvent) {
                $this->handleKey(match ($event->code) {
                    KeyCode::Down => 'j',
                    KeyCode::Up => 'k',
                    KeyCode::Enter => "\n",
                    KeyCode::Esc => 'q',
                    default => '',
                });
            }
        }

        return $handled;
    }

    /**
     * Polls keys and redraws at a rate that keeps the verify timer moving
     * without repainting for every socket tick.
     */
    public function tick(): void
    {
        $this->pollKeys();

        $now = microtime(true);

        if ($now - $this->lastDraw >= 0.25) {
            $this->draw();
        }
    }

    /**
     * Keeps the results (or an error) on screen until the operator quits or
     * asks for another scan.
     */
    public function waitForQuit(): void
    {
        if ($this->events === null) {
            return;
        }

        $this->draw();

        while (!$this->quit) {
            if ($this->pollKeys()) {
                $this->draw();
            }

            if ($this->quit) {
                break;
            }

            usleep(50_000);
        }
    }

    /**
     * Renders the current frame.
     *
     * Display::draw() renders *and* flushes, so the display is never flushed
     * again: a second flush would diff against the swapped buffer and blank
     * the screen.
     */
    public function draw(): void
    {
        $this->lastDraw = microtime(true);
        $this->renderFrame();
    }

    /**
     * One render pass. `draw()` is the name from the first task; both render
     * the same frame.
     */
    public function renderFrame(): void
    {
        $constraints = [Constraint::length($this->progressHeight())];
        $widgets = [$this->progressPane()];

        if ($this->error !== null) {
            $constraints[] = Constraint::length($this->errorHeight());
            $widgets[] = $this->errorPane();
        }

        $constraints[] = Constraint::min(0);
        $constraints[] = Constraint::length(1);
        $widgets[] = $this->findingsPane();
        $widgets[] = $this->footer();

        $this->display->draw(GridWidget::default()
            ->direction(Direction::Vertical)
            ->constraints(...$constraints)
            ->widgets(...$widgets));
    }

    private function footer(): ParagraphWidget
    {
        $key = Style::default()->fg(AnsiColor::LightCyan)->addModifier(Modifier::BOLD);
        $dim = Style::default()->fg(AnsiColor::Gray);

        return ParagraphWidget::fromLines(Line::fromSpans(
            Span::styled(' q ', $key),
            Span::styled('quit', $dim),
            Span::styled('  |  ', $dim),
            Span::styled('r', $key),
            Span::styled(' restart', $dim),
            Span::styled('  |  ', $dim),
            Span::styled('j/k', $key),
            Span::styled(' or ', $dim),
            Span::styled('↑/↓', $key),
            Span::styled(' move', $dim),
            Span::styled('  |  ', $dim),
            Span::styled('Enter', $key),
            Span::styled(' expand', $dim),
        ));
    }

    /**
     * Puts the terminal back the way it was found. Safe to call more than once.
     */
    public function stop(): void
    {
        if ($this->terminal === null || $this->stopped) {
            return;
        }

        $this->stopped = true;
        $this->terminal->disableRawMode();
        $this->terminal->queue(Actions::cursorShow(), Actions::alternateScreenDisable());
        $this->terminal->flush();
    }

    private function progressHeight(): int
    {
        return max(
            self::MIN_PROGRESS_HEIGHT,
            min(self::MAX_PROGRESS_HEIGHT, count($this->targets) + 4)
        );
    }

    private function progressPane(): BlockWidget
    {
        $header = TableRow::fromCells(
            self::cell('Target', self::headerStyle()),
            self::cell('Status', self::headerStyle()),
        );

        $rows = [];
        foreach ($this->targets as $target) {
            $phase = $this->phases[$target] ?? 'pending';
            $rows[] = TableRow::fromCells(
                self::cell($target, Style::default()->fg($this->targetColor($phase))),
                self::cell($this->phaseLabel($target, $phase), $this->phaseStyle($phase)),
            );
        }

        $table = TableWidget::default()
            ->header($header)
            ->rows(...$rows)
            ->widths(Constraint::percentage(55), Constraint::percentage(45));
        $table->columnSpacing = 1;

        $inner = GridWidget::default()
            ->direction(Direction::Vertical)
            ->constraints(Constraint::length(1), Constraint::min(0))
            ->widgets($this->gauge(), $table);

        return BlockWidget::default()
            ->borders(Borders::ALL)
            ->borderType(BorderType::Rounded)
            ->borderStyle(Style::default()->fg($this->progressColor()))
            ->titleStyle(Style::default()->fg($this->progressColor())->addModifier(Modifier::BOLD))
            ->titles(Title::fromString(' ' . $this->progressTitle() . ' '))
            ->widget($inner);
    }

    private function gauge(): GaugeWidget
    {
        $ratio = $this->total !== null && $this->total > 0
            ? ($this->done ?? 0) / $this->total
            : 0.0;

        if ($this->complete) {
            $ratio = 1.0;
        }

        $ratio = max(0.0, min(1.0, $ratio));

        $label = $this->total === null && !$this->complete
            ? 'waiting'
            : sprintf('%d%%', (int) round($ratio * 100));

        return GaugeWidget::default()
            ->ratio($ratio)
            ->label(Span::styled(
                $label,
                Style::default()->fg(AnsiColor::White)->addModifier(Modifier::BOLD)
            ))
            ->style(Style::default()->fg($this->progressColor())->bg(AnsiColor::DarkGray));
    }

    private function progressTitle(): string
    {
        if ($this->error !== null) {
            return 'PHP2Shell Scan — failed';
        }

        if ($this->complete) {
            return sprintf('PHP2Shell Scan — complete in %.1fs', $this->duration);
        }

        if ($this->verify !== []) {
            $verify = reset($this->verify);
            $elapsed = max(0, (int) (microtime(true) - $verify['started']));

            return sprintf('PHP2Shell Scan — verifying %d/%d · %ds', $verify['done'], $verify['total'], $elapsed);
        }

        if ($this->total !== null) {
            return sprintf('PHP2Shell Scan — %d/%d', $this->done ?? 0, $this->total);
        }

        return 'PHP2Shell Scan';
    }

    private function findingsPane(): BlockWidget
    {
        $lines = [];
        $selectedStart = 0;
        $row = 0;
        $width = $this->findingsWidth();

        foreach ($this->findings as $index => $finding) {
            if ($index === $this->selected) {
                $selectedStart = $row;
            }

            foreach ($this->findingLines($finding, $index === $this->selected) as $line) {
                $lines[] = $line;
                $row += $this->rowsOf($line, $width);
            }
        }

        if ($lines === []) {
            $lines[] = Line::fromSpans(Span::styled(
                $this->complete || $this->error !== null ? 'No findings.' : 'No findings yet.',
                Style::default()->fg(AnsiColor::Gray)
            ));
        }

        $paragraph = ParagraphWidget::fromLines(...$lines)->wrap(Wrap::WordTrimmed);

        // Keep the selected finding in view.
        $paragraph->scroll = [max(0, $selectedStart - $this->findingsHeight() + 1), 0];

        return BlockWidget::default()
            ->borders(Borders::ALL)
            ->borderType(BorderType::Rounded)
            ->borderStyle(Style::default()->fg($this->accentColor()))
            ->titleStyle(Style::default()->fg($this->accentColor())->addModifier(Modifier::BOLD))
            ->titles(Title::fromString(' ' . $this->findingsTitle() . ' '))
            ->widget($paragraph);
    }

    private function errorPane(): BlockWidget
    {
        $lines = [];
        foreach (preg_split('/\R/', $this->error ?? '') ?: [] as $line) {
            $lines[] = Line::fromSpans(Span::styled(
                $line,
                Style::default()->fg(AnsiColor::LightRed)->addModifier(Modifier::BOLD)
            ));
        }

        $lines[] = Line::fromString('');
        $lines[] = Line::fromSpans(
            Span::styled('Press ', Style::default()->fg(AnsiColor::Gray)),
            Span::styled('q', Style::default()->fg(AnsiColor::LightCyan)->addModifier(Modifier::BOLD)),
            Span::styled(' to exit or ', Style::default()->fg(AnsiColor::Gray)),
            Span::styled('r', Style::default()->fg(AnsiColor::LightCyan)->addModifier(Modifier::BOLD)),
            Span::styled(' to retry.', Style::default()->fg(AnsiColor::Gray)),
        );

        return BlockWidget::default()
            ->borders(Borders::ALL)
            ->borderType(BorderType::Rounded)
            ->borderStyle(Style::default()->fg(AnsiColor::Red)->addModifier(Modifier::BOLD))
            ->titleStyle(Style::default()->fg(AnsiColor::LightRed)->addModifier(Modifier::BOLD))
            ->titles(Title::fromString(' Error '))
            ->widget(ParagraphWidget::fromLines(...$lines)->wrap(Wrap::WordTrimmed));
    }

    /**
     * @return list<Line>
     */
    private function findingLines(Finding $finding, bool $isSelected): array
    {
        $severity = self::color($finding->severity);
        $markerStyle = Style::default()
            ->fg($isSelected ? AnsiColor::LightCyan : AnsiColor::DarkGray)
            ->addModifier(Modifier::BOLD);
        $labelStyle = Style::default()
            ->fg($severity)
            ->addModifier(Modifier::BOLD);
        $titleStyle = Style::default()->fg(AnsiColor::White);

        if ($isSelected) {
            $labelStyle->addModifier(Modifier::UNDERLINED);
            $titleStyle->addModifier(Modifier::BOLD);
        }

        $lines = [
            Line::fromSpans(
                Span::styled($isSelected ? '▶ ' : '  ', $markerStyle),
                Span::styled(Theme::label($finding->severity), $labelStyle),
                Span::styled('  ' . $finding->title, $titleStyle),
                Span::styled(' — ' . $finding->target, Style::default()->fg(AnsiColor::Gray)),
            ),
            Line::fromSpans(
                Span::styled('    ', Style::default()),
                Span::styled($finding->evidence, Style::default()->fg(AnsiColor::Gray)),
            ),
            Line::fromSpans(
                Span::styled('    How to exploit: ', Style::default()->fg(AnsiColor::LightYellow)),
                Span::styled($finding->exploit, Style::default()->fg(AnsiColor::White)),
            ),
        ];

        if ($this->expanded && $isSelected) {
            foreach ($finding->reproduce as $step) {
                foreach (preg_split('/\R/', $step) ?: [] as $line) {
                    $lines[] = Line::fromSpans(
                        Span::styled('    $ ', Style::default()->fg(AnsiColor::Green)->addModifier(Modifier::BOLD)),
                        Span::styled($line, Style::default()->fg(AnsiColor::LightGreen)),
                    );
                }
            }
        }

        return $lines;
    }

    private function findingsTitle(): string
    {
        $title = sprintf('Findings (%d)', count($this->findings));

        if ($this->complete || $this->error !== null) {
            if ($this->unreachableCount > 0) {
                $title .= sprintf(' · %d unreachable', $this->unreachableCount);
            }

            if ($this->unscannableCount > 0) {
                $title .= sprintf(' · %d blocked', $this->unscannableCount);
            }
        }

        return $title;
    }

    /**
     * The color of the frame's accent, based on the highest severity found.
     */
    private function accentColor(): AnsiColor
    {
        if ($this->error !== null) {
            return AnsiColor::Red;
        }

        $highest = null;
        foreach ($this->findings as $finding) {
            if ($highest === null || $finding->severity->rank() > $highest->rank()) {
                $highest = $finding->severity;
            }
        }

        if ($highest !== null) {
            return self::color($highest);
        }

        return $this->complete ? AnsiColor::Green : AnsiColor::LightBlue;
    }

    private function progressColor(): AnsiColor
    {
        if ($this->error !== null) {
            return AnsiColor::Red;
        }

        if ($this->verify !== []) {
            return AnsiColor::Yellow;
        }

        return $this->complete ? AnsiColor::Green : AnsiColor::LightBlue;
    }

    private function phaseLabel(string $target, string $phase): string
    {
        if ($phase === 'verify') {
            $verify = $this->verify[$target] ?? null;

            if ($verify === null) {
                return '◐ verify';
            }

            $elapsed = max(0, (int) (microtime(true) - $verify['started']));

            return sprintf('◐ verify %d/%d · %ds', $verify['done'], $verify['total'], $elapsed);
        }

        return match ($phase) {
            'pending' => '○ pending',
            'baseline' => '◔ baseline',
            'probe' => '◑ probe',
            'analyse' => '◕ analyse',
            'done' => '✓ done',
            'unreachable' => '✗ unreachable',
            'blocked' => '⊘ blocked',
            default => $phase,
        };
    }

    private function phaseColor(string $phase): AnsiColor
    {
        return match ($phase) {
            'pending' => AnsiColor::DarkGray,
            'baseline' => AnsiColor::Cyan,
            'probe' => AnsiColor::LightBlue,
            'analyse' => AnsiColor::Yellow,
            'verify' => AnsiColor::Yellow,
            'done' => AnsiColor::Green,
            'unreachable' => AnsiColor::Red,
            'blocked' => AnsiColor::Magenta,
            default => AnsiColor::Gray,
        };
    }

    private function phaseStyle(string $phase): Style
    {
        $style = Style::default()->fg($this->phaseColor($phase));

        return $phase === 'pending'
            ? $style->addModifier(Modifier::DIM)
            : $style->addModifier(Modifier::BOLD);
    }

    private function targetColor(string $phase): AnsiColor
    {
        return match ($phase) {
            'pending' => AnsiColor::DarkGray,
            'unreachable' => AnsiColor::Red,
            'blocked' => AnsiColor::Magenta,
            'done' => AnsiColor::White,
            default => AnsiColor::LightBlue,
        };
    }

    private static function headerStyle(): Style
    {
        return Style::default()->fg(AnsiColor::Gray)->addModifier(Modifier::BOLD);
    }

    private static function cell(string $text, Style $style): TableCell
    {
        return TableCell::fromLine(Line::fromSpans(Span::styled($text, $style)));
    }

    /**
     * The number of lines the findings pane can show.
     */
    private function findingsHeight(): int
    {
        return max(1, $this->display->viewportArea()->height - $this->progressHeight() - $this->errorHeight() - 3);
    }

    /**
     * Size the error pane to its message: borders, message rows, a blank
     * separator and the quit hint.
     */
    private function errorHeight(): int
    {
        if ($this->error === null) {
            return 0;
        }

        $width = max(1, $this->display->viewportArea()->width - 2);
        $rows = 0;

        foreach (preg_split('/\R/', $this->error) ?: [] as $line) {
            $rows += max(1, (int) ceil(mb_strlen($line) / $width));
        }

        return max(5, min(9, $rows + 4));
    }

    /**
     * The number of columns the findings pane can show.
     */
    private function findingsWidth(): int
    {
        return max(1, $this->display->viewportArea()->width - 2);
    }

    /**
     * How many rows a line takes: a line that is wider than the pane is
     * wrapped over several rows.
     */
    private function rowsOf(Line $line, int $width): int
    {
        return max(1, (int) ceil($line->width() / $width));
    }

    private static function color(Severity $severity): AnsiColor
    {
        return match ($severity) {
            Severity::Critical => AnsiColor::Red,
            Severity::High => AnsiColor::LightRed,
            Severity::Medium => AnsiColor::Yellow,
            Severity::Low => AnsiColor::Cyan,
            Severity::Info => AnsiColor::Green,
        };
    }
}
