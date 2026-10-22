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
use PhpTui\Tui\Extension\Core\Widget\GridWidget;
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
use PhpTui\Tui\Widget\Direction;
use PhpTui\Term\Actions;
use PhpTui\Term\Event\CharKeyEvent;
use PhpTui\Term\Event\CodedKeyEvent;
use PhpTui\Term\EventProvider;
use PhpTui\Term\KeyCode;
use PhpTui\Term\KeyModifiers;
use PhpTui\Term\Terminal;

/**
 * The live view: a progress pane on top and the findings below it.
 *
 * The renderer never runs a loop of its own. The scan drives it: the engine
 * reports every settled request, and the caller redraws the frame from that
 * callback. A renderer without a terminal (a DummyBackend in the tests) still
 * renders, it just cannot read any keys.
 */
final class TuiRenderer
{
    /**
     * The height of the progress pane, in rows.
     */
    private const PROGRESS_HEIGHT = 6;

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
    private bool $save = false;
    private ?int $done = null;
    private ?int $total = null;

    private Display $display;
    private ?Terminal $terminal = null;
    private ?EventProvider $events = null;

    /**
     * The event source is injectable so the key handling can be tested
     * without a terminal; the real one reads the terminal created above.
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
        $this->targets = $targets;
        $this->phases = array_fill_keys($targets, 'pending');
        $this->done = null;
        $this->total = null;

        if ($this->terminal === null) {
            return;
        }

        $this->terminal->queue(Actions::alternateScreenEnable(), Actions::cursorHide());
        $this->terminal->flush();
        $this->terminal->enableRawMode();
    }

    public function update(string $targetLabel, string $phase, ?int $done = null, ?int $total = null): void
    {
        $this->phases[$targetLabel] = $phase;
        $this->done = $done ?? $this->done;
        $this->total = $total ?? $this->total;
    }

    /**
     * @param list<Finding> $findings
     */
    public function setFindings(array $findings): void
    {
        $this->findings = $findings;
        $this->selected = 0;
        $this->expanded = false;
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

    public function requestQuit(): void
    {
        $this->quit = true;
    }

    public function handleKey(string $key): void
    {
        match ($key) {
            'q' => $this->quit = true,
            'j' => $this->move(1),
            'k' => $this->move(-1),
            'r', "\n" => $this->toggleExpanded(),
            's' => $this->save = true,
            default => null,
        };
    }

    public function saveRequested(): bool
    {
        return $this->save;
    }

    /**
     * Drains the pending terminal events.
     *
     * The event source is non-blocking, and a renderer without one (the
     * DummyBackend in tests) has nothing to drain, so this never waits.
     */
    public function pollKeys(): void
    {
        if ($this->events === null) {
            return;
        }

        while (($event = $this->events->next()) !== null) {
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
                    KeyCode::Enter => 'r',
                    KeyCode::Esc => 'q',
                    default => '',
                });
            }
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
        $this->renderFrame();
    }

    /**
     * One render pass. `draw()` is the name from the first task; both render
     * the same frame.
     */
    public function renderFrame(): void
    {
        $this->display->draw(GridWidget::default()
            ->direction(Direction::Vertical)
            ->constraints(
                Constraint::length(self::PROGRESS_HEIGHT),
                Constraint::min(0),
                Constraint::length(1)
            )
            ->widgets($this->progressPane(), $this->findingsPane(), $this->footer()));
    }

    private function footer(): ParagraphWidget
    {
        return ParagraphWidget::fromString(' q quit | j/k or arrows move | Enter expand ');
    }

    /**
     * Puts the terminal back the way it was found.
     */
    public function stop(): void
    {
        if ($this->terminal === null) {
            return;
        }

        $this->terminal->disableRawMode();
        $this->terminal->queue(Actions::cursorShow(), Actions::alternateScreenDisable());
        $this->terminal->flush();
    }

    private function progressPane(): BlockWidget
    {
        $rows = [];

        foreach ($this->targets as $target) {
            $rows[] = TableRow::fromCells(
                TableCell::fromString($target),
                TableCell::fromString($this->phases[$target] ?? 'pending'),
            );
        }

        $table = TableWidget::default()
            ->rows(...$rows)
            ->widths(Constraint::percentage(60), Constraint::percentage(40));

        return BlockWidget::default()
            ->borders(Borders::ALL)
            ->titles(Title::fromString($this->progressTitle()))
            ->widget($table);
    }

    private function progressTitle(): string
    {
        $title = 'PHP2Shell Scan';

        if ($this->total !== null) {
            $title .= sprintf(' — %d/%d', $this->done ?? 0, $this->total);
        }

        return $title;
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
            $lines[] = Line::fromString('No findings yet.');
        }

        $paragraph = ParagraphWidget::fromLines(...$lines);

        // Keep the selected finding in view.
        $paragraph->scroll = [max(0, $selectedStart - $this->findingsHeight() + 1), 0];

        return BlockWidget::default()
            ->borders(Borders::ALL)
            ->titles(Title::fromString($this->findingsTitle()))
            ->widget($paragraph);
    }

    /**
     * @return list<Line>
     */
    private function findingLines(Finding $finding, bool $isSelected): array
    {
        $style = Style::default()->fg(self::color($finding->severity));
        if ($isSelected) {
            $style = $style->addModifier(Modifier::BOLD);
        }

        $marker = $isSelected ? '>' : ' ';

        $lines = [
            Line::fromSpans(
                Span::styled($marker . ' ', $style),
                Span::styled(Theme::label($finding->severity), $style),
                Span::fromString('  ' . $finding->title . ' — ' . $finding->target),
            ),
            Line::fromString('    ' . $finding->evidence),
            Line::fromString('    How to exploit: ' . $finding->exploit),
        ];

        if ($this->expanded && $isSelected) {
            foreach ($finding->reproduce as $step) {
                $lines[] = Line::fromString('    $ ' . $step);
            }
        }

        return $lines;
    }

    private function findingsTitle(): string
    {
        return sprintf('Findings (%d)', count($this->findings));
    }

    /**
     * The number of lines the findings pane can show.
     */
    private function findingsHeight(): int
    {
        return max(1, $this->display->viewportArea()->height - self::PROGRESS_HEIGHT - 3);
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
