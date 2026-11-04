<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Metadata;

use DateTimeImmutable;

/**
 * What the rule against a rollback reads of a metadata document (spec/saml.md S-6). Whether the document was read
 * signed is said by its reading, never by whoever replaces the accepted document.
 */
interface PeerMetadataInterface
{
    public string $entityId { get; }

    public ?DateTimeImmutable $validUntil { get; }

    public bool $readSigned { get; }
}
