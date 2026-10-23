<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Metadata;

use DateTimeImmutable;

/**
 * What the rule against a rollback reads of a metadata document of a peer, whichever its role (spec/saml.md S-6,
 * section 5.2): the entity ID of the document, its `validUntil`, null when it carries none, and whether the reading
 * verified it under the certificates the declaration pins, which the reading says and never whoever replaces the
 * document accepted.
 */
interface PeerMetadataInterface
{
    public string $entityId { get; }

    public ?DateTimeImmutable $validUntil { get; }

    public bool $readSigned { get; }
}
