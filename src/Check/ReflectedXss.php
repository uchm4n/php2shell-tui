<?php

declare(strict_types=1);

namespace Php2Scan\Check;

use Php2Scan\Severity;
use Psr\Http\Message\ResponseInterface;

final class ReflectedXss extends ParameterProbe
{
    protected function probeId(): string
    {
        return 'reflected_xss';
    }

    protected function probeTitle(): string
    {
        return 'Reflected XSS';
    }

    protected function severity(): Severity
    {
        return Severity::Medium;
    }

    protected function payloads(string $marker): array
    {
        return [$marker];
    }

    protected function isConfirmed(ResponseInterface $baseline, ResponseInterface $mutated, string $mutatedUrl, string $marker): bool
    {
        // The marker contains "<" and ">", so an HTML-escaping page no longer
        // carries the literal string and this returns false.
        return str_contains((string) $mutated->getBody(), $marker);
    }

    protected function evidence(ResponseInterface $baseline, ResponseInterface $mutated, string $mutatedUrl): string
    {
        return sprintf('The marker is reflected unencoded in the response at %s.', $mutatedUrl);
    }

    protected function exploit(string $mutatedUrl): string
    {
        return sprintf('Deliver %s to a victim - the payload executes in the page origin with the victim session.', $mutatedUrl);
    }
}
