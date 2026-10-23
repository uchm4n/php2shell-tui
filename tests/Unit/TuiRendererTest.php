<?php

declare(strict_types=1);

namespace Php2ShellTui\Tests\Unit;

use Php2ShellTui\Finding;
use Php2ShellTui\Severity;
use Php2ShellTui\Tests\Fixture\FakeEventProvider;
use Php2ShellTui\Ui\TuiRenderer;
use PHPUnit\Framework\TestCase;
use PhpTui\Term\Event\CharKeyEvent;
use PhpTui\Term\Event\CodedKeyEvent;
use PhpTui\Term\KeyCode;
use PhpTui\Term\KeyModifiers;
use PhpTui\Tui\Display\Backend\DummyBackend;

final class TuiRendererTest extends TestCase
{
    public function testItRendersTheTargetsAndTheFindings(): void
    {
        $backend = new DummyBackend(100, 30);
        $renderer = new TuiRenderer($backend);
        $renderer->start(['legacy.example.com']);
        $renderer->update('legacy.example.com', 'probing');
        $renderer->setFindings([
            new Finding(
                id: 'php2shell-version',
                title: 'PHP2Shell · CVE-2026-109618',
                severity: Severity::Critical,
                target: 'legacy.example.com',
                evidence: 'PHP 8.1.29 detected via X-Powered-By (confidence: high); affected; this branch has no fixed release, upgrade to 8.2.35 or newer.',
                exploit: 'The verified public chain is Apache prefork + mod_php; FPM requires a different, unverified route.',
                reproduce: ['curl -sI https://legacy.example.com/ | grep -i x-powered-by'],
            ),
        ]);
        $renderer->draw();

        $frame = $backend->toString();

        self::assertStringContainsString('legacy.example.com', $frame);
        self::assertStringContainsString('PHP2Shell', $frame);
        self::assertStringContainsString('CRITICAL', $frame);
    }

    public function testExpandingTheSelectedFindingShowsTheReproduceSteps(): void
    {
        $backend = new DummyBackend(100, 30);
        $renderer = new TuiRenderer($backend);
        $renderer->start(['legacy.example.com']);
        $renderer->setFindings([
            new Finding(
                id: 'php2shell-version',
                title: 'PHP2Shell',
                severity: Severity::Critical,
                target: 'legacy.example.com',
                evidence: 'e',
                exploit: 'x',
                reproduce: ['curl -sS https://legacy.example.com/ | head -20'],
            ),
        ]);
        $renderer->toggleExpanded();
        $renderer->draw();

        self::assertStringContainsString('curl -sS https://legacy.example.com/', $backend->toString());
    }

    public function testTheSelectionMoves(): void
    {
        $backend = new DummyBackend(100, 30);
        $renderer = new TuiRenderer($backend);
        $renderer->start(['a.example.com', 'b.example.com']);
        $renderer->setFindings([
            new Finding('one', 'First', Severity::High, 'a.example.com', 'e', 'x', ['s']),
            new Finding('two', 'Second', Severity::Low, 'b.example.com', 'e', 'x', ['s']),
        ]);

        self::assertSame('one', $renderer->selected()?->id);
        $renderer->move(1);
        self::assertSame('two', $renderer->selected()?->id);
        $renderer->move(-5);
        self::assertSame('one', $renderer->selected()?->id);
    }

    public function testTheQKeyRequestsAQuit(): void
    {
        $backend = new DummyBackend(100, 30);
        $renderer = new TuiRenderer($backend);
        $renderer->start(['a.example.com']);

        self::assertFalse($renderer->isQuitRequested());
        $renderer->handleKey('q');
        self::assertTrue($renderer->isQuitRequested());
    }

    public function testTheRKeyRequestsARestart(): void
    {
        $backend = new DummyBackend(100, 30);
        $renderer = new TuiRenderer($backend);
        $renderer->start(['a.example.com']);

        self::assertFalse($renderer->isRestartRequested());
        $renderer->handleKey('r');
        self::assertTrue($renderer->isRestartRequested());
        self::assertTrue($renderer->isQuitRequested());
    }

    public function testTheCompletedViewShowsTheSummaryAndFinalStates(): void
    {
        $backend = new DummyBackend(100, 30);
        $renderer = new TuiRenderer($backend);
        $renderer->start(['a.example.com', 'b.example.com']);
        $renderer->setFindings([
            new Finding('one', 'First', Severity::High, 'a.example.com', 'e', 'x', ['s']),
        ]);
        $renderer->finish(['b.example.com'], [], 4.2);
        $renderer->draw();

        $frame = $backend->toString();

        self::assertStringContainsString('complete in 4.2s', $frame);
        self::assertStringContainsString('Findings (1)', $frame);
        self::assertStringContainsString('1 unreachable', $frame);
        self::assertStringContainsString('done', $frame);
        self::assertStringContainsString('unreachable', $frame);
    }

    public function testTheCompletedViewShowsBlockedTargets(): void
    {
        $backend = new DummyBackend(100, 30);
        $renderer = new TuiRenderer($backend);
        $renderer->start(['a.example.com', 'b.example.com']);
        $renderer->finish([], ['b.example.com'], 1.0);
        $renderer->draw();

        self::assertStringContainsString('1 blocked', $backend->toString());
        self::assertStringContainsString('⊘ blocked', $backend->toString());
    }

    public function testTheMostSevereFindingIsSelectedFirst(): void
    {
        $renderer = new TuiRenderer(new DummyBackend(100, 30));
        $renderer->start(['a.example.com']);
        $renderer->setFindings([
            new Finding('low', 'Low', Severity::Low, 'a.example.com', 'e', 'x', ['s']),
            new Finding('critical', 'Critical', Severity::Critical, 'a.example.com', 'e', 'x', ['s']),
        ]);

        self::assertSame('critical', $renderer->selected()?->id);
    }

    public function testTheCompletedViewSaysNoFindings(): void
    {
        $backend = new DummyBackend(100, 30);
        $renderer = new TuiRenderer($backend);
        $renderer->start(['a.example.com']);
        $renderer->finish([], [], 1.0);
        $renderer->draw();

        $frame = $backend->toString();

        self::assertStringContainsString('No findings.', $frame);
        self::assertStringNotContainsString('No findings yet.', $frame);
    }

    public function testTheErrorBannerKeepsTheFindingsVisible(): void
    {
        $backend = new DummyBackend(100, 30);
        $renderer = new TuiRenderer($backend);
        $renderer->start(['a.example.com']);
        $renderer->setFindings([
            new Finding('one', 'First', Severity::High, 'a.example.com', 'e', 'x', ['s']),
        ]);
        $renderer->fail(new \RuntimeException('report directory is not writable'));
        $renderer->draw();

        $frame = $backend->toString();

        self::assertStringContainsString('failed', $frame);
        self::assertStringContainsString('Error', $frame);
        self::assertStringContainsString('report directory is not writable', $frame);
        self::assertStringContainsString('Press q to exit', $frame);
        self::assertStringContainsString('First', $frame);
    }

    public function testPollKeysReportsWhetherAnythingHappened(): void
    {
        $events = new FakeEventProvider([CharKeyEvent::new('j')]);
        $renderer = new TuiRenderer(new DummyBackend(100, 30), $events);
        $renderer->start(['a.example.com', 'b.example.com']);
        $renderer->setFindings([
            new Finding('one', 'First', Severity::High, 'a.example.com', 'e', 'x', ['s']),
            new Finding('two', 'Second', Severity::Low, 'b.example.com', 'e', 'x', ['s']),
        ]);

        self::assertTrue($renderer->pollKeys());
        self::assertFalse($renderer->pollKeys());
    }

    public function testWaitForQuitProcessesKeysAndReturnsOnQ(): void
    {
        $events = new FakeEventProvider([
            CharKeyEvent::new('j'),
            CharKeyEvent::new('q'),
        ]);
        $renderer = new TuiRenderer(new DummyBackend(100, 30), $events);
        $renderer->start(['a.example.com', 'b.example.com']);
        $renderer->setFindings([
            new Finding('one', 'First', Severity::High, 'a.example.com', 'e', 'x', ['s']),
            new Finding('two', 'Second', Severity::Low, 'b.example.com', 'e', 'x', ['s']),
        ]);
        $renderer->finish([], [], 1.0);

        $renderer->waitForQuit();

        self::assertTrue($renderer->isQuitRequested());
        self::assertSame('two', $renderer->selected()?->id);
    }

    public function testTheTerminalEventsDriveTheKeyHandling(): void
    {
        $events = new FakeEventProvider([
            CodedKeyEvent::new(KeyCode::Down),
            CharKeyEvent::new('c', KeyModifiers::CONTROL),
        ]);
        $renderer = new TuiRenderer(new DummyBackend(100, 30), $events);
        $renderer->start(['a.example.com', 'b.example.com']);
        $renderer->setFindings([
            new Finding('one', 'First', Severity::High, 'a.example.com', 'e', 'x', ['s']),
            new Finding('two', 'Second', Severity::Low, 'b.example.com', 'e', 'x', ['s']),
        ]);

        $renderer->pollKeys();

        self::assertSame('two', $renderer->selected()?->id);
        self::assertTrue($renderer->isQuitRequested());
    }

    public function testTheFooterShowsTheQuitAndRestartHints(): void
    {
        $backend = new DummyBackend(100, 30);
        $renderer = new TuiRenderer($backend);
        $renderer->start(['a.example.com']);
        $renderer->draw();

        $frame = $backend->toString();

        self::assertStringContainsString('q quit', $frame);
        self::assertStringContainsString('r restart', $frame);
    }

    public function testTheVerifyPhaseShowsTheAttemptAndElapsedTime(): void
    {
        $backend = new DummyBackend(100, 30);
        $renderer = new TuiRenderer($backend);
        $renderer->start(['a.example.com']);
        $renderer->update('a.example.com', 'probe', 10, 10);
        $renderer->setVerify('a.example.com', 2, 5);
        $renderer->draw();

        $frame = $backend->toString();

        self::assertStringContainsString('verifying 2/5', $frame);
        self::assertStringContainsString('verify 2/5', $frame);
        self::assertStringContainsString('100%', $frame);
    }

    public function testRestartResetsTheView(): void
    {
        $backend = new DummyBackend(100, 30);
        $renderer = new TuiRenderer($backend);
        $renderer->start(['a.example.com']);
        $renderer->setFindings([
            new Finding('one', 'First', Severity::High, 'a.example.com', 'e', 'x', ['s']),
        ]);
        $renderer->finish([], [], 4.2);
        $renderer->handleKey('r');

        $renderer->restart(['a.example.com']);
        $renderer->draw();

        $frame = $backend->toString();

        self::assertFalse($renderer->isRestartRequested());
        self::assertStringContainsString('No findings yet.', $frame);
        self::assertStringContainsString('pending', $frame);
        self::assertStringNotContainsString('complete in', $frame);
        self::assertStringNotContainsString('First', $frame);
    }

    public function testWaitForQuitReturnsWhenARestartIsRequested(): void
    {
        $events = new FakeEventProvider([CharKeyEvent::new('r')]);
        $renderer = new TuiRenderer(new DummyBackend(100, 30), $events);
        $renderer->start(['a.example.com']);
        $renderer->finish([], [], 1.0);

        $renderer->waitForQuit();

        self::assertTrue($renderer->isRestartRequested());
    }

    public function testTheEscKeyRequestsAQuit(): void
    {
        $events = new FakeEventProvider([CodedKeyEvent::new(KeyCode::Esc)]);
        $renderer = new TuiRenderer(new DummyBackend(100, 30), $events);
        $renderer->start(['a.example.com']);

        $renderer->pollKeys();

        self::assertTrue($renderer->isQuitRequested());
    }

    public function testTheEnterKeyExpandsTheSelectedFinding(): void
    {
        $backend = new DummyBackend(100, 30);
        $events = new FakeEventProvider([CodedKeyEvent::new(KeyCode::Enter)]);
        $renderer = new TuiRenderer($backend, $events);
        $renderer->start(['a.example.com']);
        $renderer->setFindings([new Finding('one', 'First', Severity::High, 'a.example.com', 'e', 'x', ['s'])]);

        $renderer->pollKeys();
        $renderer->draw();

        self::assertStringContainsString('$ s', $backend->toString());
    }
}
