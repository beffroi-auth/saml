<?php

declare(strict_types=1);

namespace Beffroi\Saml\Application\ServiceProvider;

use function sprintf;

/**
 * What a refresh of the metadata of one service provider came to (spec/saml.md section 6.2): registered, refreshed,
 * unchanged, or refused with the rule that refused it, the accepted document kept. A terminal and a log read it; the
 * message names the declared entity ID and never a value of the document (M-16).
 */
final readonly class MetadataRefreshment
{
    private function __construct(
        public string $entityId,
        public bool $refused,
        public string $what,
    ) {
    }

    public static function registered(string $entityId): self
    {
        return new self($entityId, false, sprintf('The service provider "%s" is registered from its metadata.', $entityId));
    }

    public static function refreshed(string $entityId): self
    {
        return new self($entityId, false, sprintf('The metadata of the service provider "%s" are refreshed.', $entityId));
    }

    public static function unchanged(string $entityId): self
    {
        return new self($entityId, false, sprintf('The metadata of the service provider "%s" are the ones accepted already.', $entityId));
    }

    public static function refused(string $entityId, string $why): self
    {
        return new self($entityId, true, sprintf('The metadata of the service provider "%s" are refused, the document accepted kept: %s', $entityId, $why));
    }
}
