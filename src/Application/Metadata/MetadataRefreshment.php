<?php

declare(strict_types=1);

namespace Beffroi\Saml\Application\Metadata;

use Exception;
use function sprintf;

/**
 * What a refresh of the metadata of one peer came to, a service provider (spec/saml.md section 6.2) or an upstream
 * identity provider (section 6.10): registered, registered by another process meanwhile, refreshed, unchanged, refused
 * with the rule that refused it, or failed, the accepted document kept. A terminal and a log read it; the message
 * names the role and the declared entity ID, and never a value of the document (M-16).
 */
final readonly class MetadataRefreshment
{
    private function __construct(
        public string $entityId,
        public bool $refused,
        public string $what,
    ) {
    }

    /**
     * @param string $noun the words the role names a peer with, "service provider" or "identity provider"
     */
    public static function registered(string $noun, string $entityId): self
    {
        return new self($entityId, false, sprintf('The %s "%s" is registered from its metadata.', $noun, $entityId));
    }

    /**
     * Another process registered the peer between the reading of the accepted document and the write, the console
     * and the hourly step at the same minute: this reading is skipped, and refuses nothing (section 6.2 step 6).
     */
    public static function registeredMeanwhile(string $noun, string $entityId): self
    {
        return new self(
            $entityId,
            false,
            sprintf('The %s "%s" was registered by another process meanwhile; this reading is skipped.', $noun, $entityId),
        );
    }

    public static function refreshed(string $noun, string $entityId): self
    {
        return new self($entityId, false, sprintf('The metadata of the %s "%s" are refreshed.', $noun, $entityId));
    }

    public static function unchanged(string $noun, string $entityId): self
    {
        return new self($entityId, false, sprintf('The metadata of the %s "%s" are the ones accepted already.', $noun, $entityId));
    }

    public static function refused(string $noun, string $entityId, string $why): self
    {
        return new self($entityId, true, sprintf('The metadata of the %s "%s" are refused, the document accepted kept: %s', $noun, $entityId, $why));
    }

    /**
     * A reading that threw what no rule refuses, a store or a reader that failed (section 6.2): named by the class of
     * what was thrown and never by its message, which may carry a value of the document or of a query (M-16).
     */
    public static function failed(string $noun, string $entityId, Exception $failure): self
    {
        return new self(
            $entityId,
            true,
            sprintf('The metadata of the %s "%s" could not be refreshed, the document accepted kept: %s was thrown.', $noun, $entityId, $failure::class),
        );
    }
}
