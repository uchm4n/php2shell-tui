<?php

declare(strict_types=1);

namespace Php2ShellTui;

/**
 * Thrown from the TUI's key poll when the operator asks to run the scan again.
 */
final class ScanRestart extends \RuntimeException
{
}
