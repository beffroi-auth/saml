<?php

declare(strict_types=1);

namespace Beffroi\Saml\Application\ServiceProvider;

use Exception;
use function sprintf;

/**
 * What a refresh of the metadata of one service provider came to (spec/saml.md section 6.2): registered, registered by
 * another process meanwhile, refreshed, unchanged, refused with the rule that refused it, or failed, the accepted
 * document kept. A terminal and a log read it; the message names the declared entity ID and never a value of the
 * document (M-16).
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

    /**
     * Another process registered the service provider between the reading of the accepted document and the write,
     * the console and the hourly step at the same minute: this reading is skipped, and refuses nothing (section 6.2
     * step 6).
     */
    public static function registeredMeanwhile(string $entityId): self
    {
        return new self(
            $entityId,
            false,
            sprintf('The service provider "%s" was registered by another process meanwhile; this reading is skipped.', $entityId),
        );
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

    /**
     * A reading that threw what no rule refuses, a store or a reader that failed (section 6.2): named by the class of
     * what was thrown and never by its message, which may carry a value of the document or of a query (M-16).
     */
    public static function failed(string $entityId, Exception $failure): self
    {
        return new self(
            $entityId,
            true,
            sprintf('The metadata of the service provider "%s" could not be refreshed, the document accepted kept: %s was thrown.', $entityId, $failure::class),
        );
    }
}
