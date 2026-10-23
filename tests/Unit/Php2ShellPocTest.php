<?php

declare(strict_types=1);

namespace Php2ShellTui\Tests\Unit;

use GuzzleHttp\Client as GuzzleClient;
use Php2ShellTui\Http\Client;
use Php2ShellTui\Poc\Php2ShellPoc;
use Php2ShellTui\Poc\Profile;
use Php2ShellTui\Target;
use PHPUnit\Framework\TestCase;

final class Php2ShellPocTest extends TestCase
{
    private static function profile(): Profile
    {
        return Profile::fromFile(__DIR__ . '/../../src/Data/poc/php-8.4.26-apache-bookworm-amd64.json');
    }

    /**
     * @return array<string, mixed>
     */
    private static function profileData(): array
    {
        return json_decode(
            (string) file_get_contents(__DIR__ . '/../../src/Data/poc/php-8.4.26-apache-bookworm-amd64.json'),
            true,
            512,
            JSON_THROW_ON_ERROR,
        );
    }

    public function testStageOneRefusesAWorkerCapBeforeSending(): void
    {
        $result = (new Php2ShellPoc(maxWorkers: 100))->stage1(
            new Target('http://127.0.0.1:1/', postPath: '/index.php'),
            self::profile(),
        );

        self::assertFalse($result->confirmed);
        self::assertStringContainsString('worker cap', $result->reason);
    }

    public function testStageOneRefusesAnFpmProfileBeforeSending(): void
    {
        $data = self::profileData();
        $data['sapi'] = 'fpm-fcgi';

        $result = (new Php2ShellPoc())->stage1(
            new Target('http://127.0.0.1:1/', postPath: '/index.php'),
            Profile::fromArray($data),
        );

        self::assertFalse($result->confirmed);
        self::assertStringContainsString('mod_php only', $result->reason);
    }

    public function testStageOneRefusesAnUnverifiedProfileBeforeSending(): void
    {
        $data = self::profileData();
        $data['rce_verified'] = false;

        $result = (new Php2ShellPoc())->stage1(
            new Target('http://127.0.0.1:1/', postPath: '/index.php'),
            Profile::fromArray($data),
        );

        self::assertFalse($result->confirmed);
        self::assertStringContainsString('not verified', $result->reason);
    }

    public function testGuessModeAllowsAnUnverifiedProfileToReachTheWorkerGate(): void
    {
        $data = self::profileData();
        $data['rce_verified'] = false;

        $result = (new Php2ShellPoc(
            client: new Client(new GuzzleClient()),
            maxWorkers: 100,
        ))->run(
            new Target('http://127.0.0.1:1/', postPath: '/index.php'),
            Profile::fromArray($data),
            allowUnverified: true,
        );

        self::assertFalse($result->confirmed);
        self::assertStringContainsString('worker cap', $result->reason);
    }

    public function testAnUnverifiedProfileIsRefusedWithoutTheGuessFlag(): void
    {
        $data = self::profileData();
        $data['rce_verified'] = false;

        $result = (new Php2ShellPoc())->run(
            new Target('http://127.0.0.1:1/', postPath: '/index.php'),
            Profile::fromArray($data),
        );

        self::assertFalse($result->confirmed);
        self::assertStringContainsString('not verified', $result->reason);
    }
}
