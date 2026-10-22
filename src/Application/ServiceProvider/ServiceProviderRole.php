<?php

declare(strict_types=1);

namespace Beffroi\Saml\Application\ServiceProvider;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Application\Metadata\PeerRoleInterface;
use Beffroi\Saml\Domain\Metadata\PeerInterface;
use Beffroi\Saml\Domain\Metadata\PeerMetadataInterface;
use Beffroi\Saml\Domain\ServiceProvider\AcceptedServiceProviderMetadata;
use Beffroi\Saml\Domain\ServiceProvider\AuthnRequestSigning;
use Beffroi\Saml\Domain\ServiceProvider\ServiceProvider;
use Beffroi\Saml\Domain\ServiceProvider\ServiceProviderMetadata;
use Beffroi\Saml\Exception\MetadataRefusedException;
use Beffroi\Saml\Port\ServiceProviderMetadataReaderInterface;
use Beffroi\Saml\Port\ServiceProvidersInterface;
use DateTimeImmutable;
use Symfony\Component\Uid\Uuid;

/**
 * The service providers of a tenant as a role of the peers whose metadata are read (spec/saml.md section 6.2): those
 * the configuration declares (S-5), a document of one read by the channel or under the signers it pins, its entity ID
 * the declared one, refused when it asks for encryption without a key for it (S-7) and when its requests need a
 * signature without a key to verify it by (S-11), and its first document kept in the row of the service providers.
 *
 * @implements PeerRoleInterface<ServiceProvider>
 */
final readonly class ServiceProviderRole implements PeerRoleInterface
{
    public function __construct(
        private ServiceProvidersInterface $serviceProviders,
        private ServiceProviderMetadataReaderInterface $reader,
    ) {
    }

    public function noun(): string
    {
        return 'service provider';
    }

    public function of(Tenant $tenant): array
    {
        return $this->serviceProviders->of($tenant);
    }

    /**
     * Section 6.2 steps 3 to 5.
     *
     * @param ServiceProvider $peer
     */
    public function read(PeerInterface $peer, string $document): ServiceProviderMetadata
    {
        $metadata = $peer->readsSigned() ? $this->reader->readSigned($document, $peer->metadataSigners) : $this->reader->readTrusted($document);
        if ($metadata->entityId !== $peer->entityId) {
            throw new MetadataRefusedException('The metadata name another entity than the service provider declared (spec/saml.md S-5).');
        }
        if ($peer->encryptAssertions && $metadata->encryptionCertificates === []) {
            throw new MetadataRefusedException('The service provider asks for encrypted assertions and its metadata hold no key for encryption (spec/saml.md S-7).');
        }
        if ($metadata->signingCertificates === [] && AuthnRequestSigning::of($peer, $metadata)->required) {
            throw new MetadataRefusedException('The requests of the service provider need a signature and its metadata hold no key for signing (spec/saml.md S-11).');
        }

        return $metadata;
    }

    public function accepted(Tenant $tenant, PeerMetadataInterface $metadata, string $document, DateTimeImmutable $at): AcceptedServiceProviderMetadata
    {
        return new AcceptedServiceProviderMetadata(Uuid::v7(), $tenant, $metadata->entityId, $document, $metadata->validUntil, $at);
    }
}
