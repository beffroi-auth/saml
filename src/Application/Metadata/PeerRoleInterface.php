<?php

declare(strict_types=1);

namespace Beffroi\Saml\Application\Metadata;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\Metadata\AcceptedMetadata;
use Beffroi\Saml\Domain\Metadata\PeerInterface;
use Beffroi\Saml\Domain\Metadata\PeerMetadataInterface;
use Beffroi\Saml\Exception\MetadataRefusedException;
use DateTimeImmutable;

/**
 * One role of the peers of a tenant whose metadata are read, the service providers (spec/saml.md section 6.2) or the
 * upstream identity providers (section 6.10): what a refresh asks of a role and of nothing else, so that the procedure
 * of section 6.2, the rule against a rollback among it, is written once for both (S-42).
 *
 * @template TPeer of PeerInterface
 */
interface PeerRoleInterface
{
    /**
     * The words an outcome names a peer of this role with, "service provider" or "identity provider".
     */
    public function noun(): string;

    /**
     * The peers of this role the tenant declares, in the order of the declaration.
     *
     * @return list<TPeer>
     */
    public function of(Tenant $tenant): array;

    /**
     * A document of that peer read, by readSigned() under the signers its declaration pins or by readTrusted(), and
     * held to what this role requires of it: its entity ID the declared one, its role in it, its keys and its
     * endpoints (section 6.2 steps 3 to 5, section 6.10 steps 3 and 4).
     *
     * @param TPeer $peer
     *
     * @throws MetadataRefusedException
     */
    public function read(PeerInterface $peer, string $document): PeerMetadataInterface;

    /**
     * The row of this role that keeps the first document accepted for a peer, its bytes as they were read (S-8).
     */
    public function accepted(Tenant $tenant, PeerMetadataInterface $metadata, string $document, DateTimeImmutable $at): AcceptedMetadata;
}
