<?php

declare(strict_types=1);

namespace Php2ShellTui\Tests\Unit;

use Php2ShellTui\Poc\ProofPath;
use PHPUnit\Framework\TestCase;

final class ProofPathTest extends TestCase
{
    public function testItReturnsTheScriptDirectoryAndRootCandidates(): void
    {
        self::assertSame(['/app/p', '/p'], ProofPath::candidates('/app/index.php', 'p'));
        self::assertSame(['/p'], ProofPath::candidates('/index.php', 'p'));
        self::assertSame(['/app/p', '/p'], ProofPath::candidates('/app/index.php?x=1', 'p'));
    }

    public function testItRejectsUnsafeFileNames(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        ProofPath::candidates('/index.php', '../p');
    }

    public function testRandomFileIsASafeShortName(): void
    {
        self::assertMatchesRegularExpression('/^[a-z0-9]$/', ProofPath::randomFile());
    }
}
