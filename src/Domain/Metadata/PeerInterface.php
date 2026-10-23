<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Metadata;

/**
 * What a refresh reads of the declaration of a peer of the tenant, whichever its role (spec/saml.md section 5.2): a
 * service provider (S-5) or an upstream identity provider (S-42), each declared in the configuration of the
 * deployment and nowhere else. Its entity ID, where its metadata are read from, and the certificates that sign them,
 * none when the channel they come through vouches for them.
 */
interface PeerInterface
{
    public string $entityId { get; }

    public MetadataLocation $metadata { get; }

    /**
     * @var list<Certificate>
     */
    public array $metadataSigners { get; }

    /**
     * Whether its metadata are verified under the signers it pins, `readSigned()`, rather than trusted by the channel
     * they come through, `readTrusted()` (S-5, S-42).
     */
    public function readsSigned(): bool;
}
