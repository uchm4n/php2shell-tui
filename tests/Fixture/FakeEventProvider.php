<?php

declare(strict_types=1);

namespace Php2Scan\Tests\Fixture;

use PhpTui\Term\Event;
use PhpTui\Term\EventProvider;

/**
 * Hands out a fixed list of terminal events, so the key handling can be
 * tested without a terminal.
 */
final class FakeEventProvider implements EventProvider
{
    /**
     * @param list<Event> $events
     */
    public function __construct(private array $events)
    {
    }

    public function next(): ?Event
    {
        return array_shift($this->events);
    }
}
