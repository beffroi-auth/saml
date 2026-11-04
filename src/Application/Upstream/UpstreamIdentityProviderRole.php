<?php

declare(strict_types=1);

namespace Beffroi\Saml\Application\Upstream;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Application\Metadata\PeerRoleInterface;
use Beffroi\Saml\Domain\Metadata\PeerInterface;
use Beffroi\Saml\Domain\Metadata\PeerMetadataInterface;
use Beffroi\Saml\Domain\Upstream\AcceptedUpstreamMetadata;
use Beffroi\Saml\Domain\Upstream\UpstreamIdentityProvider;
use Beffroi\Saml\Domain\Upstream\UpstreamMetadata;
use Beffroi\Saml\Exception\MetadataRefusedException;
use Beffroi\Saml\Port\UpstreamIdentityProvidersInterface;
use Beffroi\Saml\Port\UpstreamMetadataReaderInterface;
use DateTimeImmutable;
use Symfony\Component\Uid\Uuid;

/**
 * spec/saml.md section 6.10, S-42, S-43
 *
 * @implements PeerRoleInterface<UpstreamIdentityProvider>
 */
final readonly class UpstreamIdentityProviderRole implements PeerRoleInterface
{
    public function __construct(
        private UpstreamIdentityProvidersInterface $identityProviders,
        private UpstreamMetadataReaderInterface $reader,
    ) {
    }

    public function noun(): string
    {
        return 'identity provider';
    }

    public function of(Tenant $tenant): array
    {
        return $this->identityProviders->of($tenant);
    }

    /**
     * Section 6.10 steps 3 and 4
     */
    public function read(PeerInterface $peer, string $document): UpstreamMetadata
    {
        if (! $peer instanceof UpstreamIdentityProvider) {
            throw new InvalidArgumentException('The role of the upstream identity providers reads the metadata of an upstream identity provider (spec/saml.md section 6.10).');
        }
        $metadata = $peer->readsSigned() ? $this->reader->readSigned($document, $peer->metadataSigners) : $this->reader->readTrusted($document);
        if ($metadata->entityId !== $peer->entityId) {
            throw new MetadataRefusedException('The metadata name another entity than the identity provider declared (spec/saml.md S-42).');
        }

        return $metadata;
    }

    public function accepted(Tenant $tenant, PeerMetadataInterface $metadata, string $document, DateTimeImmutable $at): AcceptedUpstreamMetadata
    {
        return new AcceptedUpstreamMetadata(Uuid::v7(), $tenant, $metadata->entityId, $document, $metadata->validUntil, $at);
    }
}
