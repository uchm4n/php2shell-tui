<?php

declare(strict_types=1);

namespace Php2ShellTui;

use Php2ShellTui\Command\ScanCommand;
use Symfony\Component\Console\Application as BaseApplication;

final class Application extends BaseApplication
{
    public const NAME = 'php2shell-tui';
    public const VERSION = '0.0.1';

    public function __construct()
    {
        parent::__construct(self::NAME, self::VERSION);
        $this->add(new ScanCommand());
        $this->setDefaultCommand('scan');
    }
}
