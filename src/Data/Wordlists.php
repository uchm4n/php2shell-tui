<?php

declare(strict_types=1);

namespace Php2ShellTui\Data;

final class Wordlists
{
    public function __construct(private readonly string $dataDir)
    {
    }

    /**
     * @return list<string>
     */
    public function sensitivePaths(): array
    {
        return $this->lines('sensitive-paths.txt');
    }

    /**
     * @return list<string>
     */
    public function webshellPaths(): array
    {
        return $this->lines('webshell-paths.txt');
    }

    /**
     * @return list<int>
     */
    public function openPorts(): array
    {
        return array_map('intval', $this->lines('open-ports.txt'));
    }

    /**
     * @return list<string>
     */
    public function lines(string $file): array
    {
        $path = $this->dataDir . '/' . $file;
        $raw = @file_get_contents($path);

        if ($raw === false) {
            return [];
        }

        $lines = [];

        foreach (preg_split('/\R/', $raw) ?: [] as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            $lines[] = $line;
        }

        return $lines;
    }
}
