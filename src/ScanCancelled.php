<?php

declare(strict_types=1);

namespace Php2ShellTui;

/**
 * Thrown from the TUI's key poll when the operator asks to stop the scan.
 */
final class ScanCancelled extends \RuntimeException
{
}
