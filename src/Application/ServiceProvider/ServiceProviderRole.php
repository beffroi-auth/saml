<?php

declare(strict_types=1);

namespace Beffroi\Saml\Application\ServiceProvider;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
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
 * spec/saml.md section 6.2, S-5, S-7, S-11
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
     * Section 6.2 steps 3 to 5
     */
    public function read(PeerInterface $peer, string $document): ServiceProviderMetadata
    {
        if (! $peer instanceof ServiceProvider) {
            throw new InvalidArgumentException('The role of the service providers reads the metadata of a service provider (spec/saml.md section 6.2).');
        }
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
