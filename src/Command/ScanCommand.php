<?php

declare(strict_types=1);

namespace Php2Scan\Command;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'scan', description: 'Scan the configured hosts for security exposure')]
final class ScanCommand extends Command
{
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $output->writeln('<info>php2scan: not yet implemented</info>');

        return Command::SUCCESS;
    }
}
