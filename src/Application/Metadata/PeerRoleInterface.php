<?php

declare(strict_types=1);

namespace Beffroi\Saml\Application\Metadata;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\Metadata\AcceptedMetadata;
use Beffroi\Saml\Domain\Metadata\PeerInterface;
use Beffroi\Saml\Domain\Metadata\PeerMetadataInterface;
use Beffroi\Saml\Exception\MetadataRefusedException;
use DateTimeImmutable;

/**
 * spec/saml.md section 6.2, section 6.10, S-42
 *
 * @template TPeer of PeerInterface
 */
interface PeerRoleInterface
{
    /**
     * The words naming a peer of this role: "service provider" or "identity provider".
     */
    public function noun(): string;

    /**
     * @return list<TPeer> in the order of the declaration
     */
    public function of(Tenant $tenant): array;

    /**
     * Section 6.2 steps 3 to 5, section 6.10 steps 3 and 4
     *
     * @throws MetadataRefusedException
     * @throws InvalidArgumentException when the peer is one of another role
     */
    public function read(PeerInterface $peer, string $document): PeerMetadataInterface;

    /**
     * S-8
     */
    public function accepted(Tenant $tenant, PeerMetadataInterface $metadata, string $document, DateTimeImmutable $at): AcceptedMetadata;
}
