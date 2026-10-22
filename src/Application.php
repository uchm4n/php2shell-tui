<?php

declare(strict_types=1);

namespace Php2Scan;

use Php2Scan\Command\ScanCommand;
use Symfony\Component\Console\Application as BaseApplication;

final class Application extends BaseApplication
{
    public const NAME = 'php2scan';
    public const VERSION = '0.0.1';

    public function __construct()
    {
        parent::__construct(self::NAME, self::VERSION);
        $this->add(new ScanCommand());
    }
}
