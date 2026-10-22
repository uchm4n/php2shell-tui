<?php

declare(strict_types=1);

// aidantwoods/secureheaders emits PHP 8.5 deprecations at class-load time.
// Suppress them before the class is ever autoloaded so the test output stays pristine.
error_reporting(E_ALL & ~E_DEPRECATED);

require __DIR__ . '/../vendor/autoload.php';

// PHPUnit installs its own error handler around every test and reports
// deprecations regardless of error_reporting(), so masking E_DEPRECATED above is
// not enough. Compiling the vendor classes here - before PHPUnit is running and
// while E_DEPRECATED is still masked - emits the deprecations exactly once, where
// nobody reports them.
Aidantwoods\SecureHeaders\Validator::validate(new Aidantwoods\SecureHeaders\HeaderBag(['X-Warmup' => '1']));
