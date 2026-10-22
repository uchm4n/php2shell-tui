<?php

declare(strict_types=1);

namespace Php2Scan\Ui;

use Symfony\Component\Console\Output\OutputInterface;

final class PlainRenderer
{
    public function render(string $text, OutputInterface $output): void
    {
        $output->write($text);
    }
}
