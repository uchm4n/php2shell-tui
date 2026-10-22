<?php

declare(strict_types=1);

namespace Php2Scan;

/**
 * Thrown from the TUI's key poll when the operator asks to stop the scan.
 */
final class ScanCancelled extends \RuntimeException
{
}
