<?php

declare(strict_types=1);

namespace Beffroi\Saml\Application\Metadata;

use Exception;
use function sprintf;

/**
 * spec/saml.md section 6.2, section 6.10
 *
 * Its message names the role and the declared entity ID, never a value of the document (M-16).
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
     * @param string $noun "service provider" or "identity provider"
     */
    public static function registered(string $noun, string $entityId): self
    {
        return new self($entityId, false, sprintf('The %s "%s" is registered from its metadata.', $noun, $entityId));
    }

    /**
     * Section 6.2 step 6
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
     * Named by the class of what was thrown, never by its message, which may carry a value of the document (M-16).
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
