<?php

declare(strict_types=1);

namespace Php2ShellTui\Check;

interface ProgressAware
{
    /**
     * @param null|callable(string, string, int, int): void $onProgress
     * @param null|callable(): void                        $onTick
     */
    public function setProgress(?callable $onProgress, ?callable $onTick): void;
}
