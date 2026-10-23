<?php

declare(strict_types=1);

namespace Php2ShellTui\Poc;

final class ProofPath
{
    public static function randomFile(): string
    {
        $alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';

        return $alphabet[random_int(0, strlen($alphabet) - 1)];
    }

    /**
     * @return list<string>
     */
    public static function candidates(string $postPath, string $file): array
    {
        if (preg_match('/^[a-z0-9]{1,2}$/', $file) !== 1) {
            throw new \InvalidArgumentException('Proof file name must be one or two lowercase alphanumeric characters.');
        }

        $path = strtok($postPath, '?') ?: '/';

        if ($path === '' || $path[0] !== '/') {
            $path = '/' . $path;
        }

        $directory = dirname($path);
        $directory = $directory === '.' || $directory === '\\' ? '/' : rtrim($directory, '/');

        return array_values(array_unique([
            $directory . '/' . $file,
            '/' . $file,
        ]));
    }
}
