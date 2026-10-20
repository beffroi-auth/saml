<?php

declare(strict_types=1);

namespace Beffroi\Saml\Application\ServiceProvider;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\ServiceProvider\AcceptedMetadata;
use Beffroi\Saml\Domain\ServiceProvider\AuthnRequestSigning;
use Beffroi\Saml\Domain\ServiceProvider\ServiceProvider;
use Beffroi\Saml\Domain\ServiceProvider\ServiceProviderMetadata;
use Beffroi\Saml\Exception\MetadataRefusedException;
use Beffroi\Saml\Port\AcceptedMetadataRepositoryInterface;
use Beffroi\Saml\Port\MetadataFetcherInterface;
use Beffroi\Saml\Port\ServiceProviderMetadataReaderInterface;
use Beffroi\Saml\Port\ServiceProvidersInterface;
use Exception;
use Psr\Clock\ClockInterface;
use Symfony\Component\Uid\Uuid;

/**
 * The metadata of a service provider registered the first time and refreshed every time after, one procedure
 * (spec/saml.md section 6.2): read from the location its declaration names, by the channel or under the signers it
 * pins (S-5), never expired, nor older than the document accepted when it was read under those signers (S-6), refused
 * when it asks for encryption without a key for it (S-7) and when its requests need a signature without a key to
 * verify it by (S-11), and kept as the bytes that were read (S-8).
 *
 * A refusal leaves the accepted document as it was and is returned rather than thrown, so that a refresh of every
 * service provider reads each of them whatever one answers.
 */
final readonly class ServiceProviderMetadataRefresh
{
    public function __construct(
        private ServiceProvidersInterface $serviceProviders,
        private MetadataFetcherInterface $fetcher,
        private ServiceProviderMetadataReaderInterface $reader,
        private AcceptedMetadataRepositoryInterface $accepted,
        private ClockInterface $clock,
    ) {
    }

    /**
     * Every service provider the tenant declares, in the order of the declaration, each one isolated from the others:
     * an exception that is not a refusal, a store or a reader that fails, is reported for the service provider it was
     * thrown for, and the next one is read.
     *
     * @return list<MetadataRefreshment>
     */
    public function refreshAll(Tenant $tenant): array
    {
        $refreshments = [];
        foreach ($this->serviceProviders->of($tenant) as $serviceProvider) {
            try {
                $refreshments[] = $this->refresh($tenant, $serviceProvider);
            } catch (Exception $failure) {
                $refreshments[] = MetadataRefreshment::failed($serviceProvider->entityId, $failure);
            }
        }

        return $refreshments;
    }

    public function refresh(Tenant $tenant, ServiceProvider $serviceProvider): MetadataRefreshment
    {
        try {
            return $this->accept($tenant, $serviceProvider);
        } catch (MetadataRefusedException $exception) {
            return MetadataRefreshment::refused($serviceProvider->entityId, $exception->getMessage());
        }
    }

    /**
     * Section 6.2 steps 2 to 7.
     *
     * @throws MetadataRefusedException
     */
    private function accept(Tenant $tenant, ServiceProvider $serviceProvider): MetadataRefreshment
    {
        $document = $this->fetcher->fetch($serviceProvider->metadata);
        $metadata = $this->read($serviceProvider, $document);
        $accepted = $this->accepted->find($tenant, $serviceProvider->entityId);
        if (! $accepted instanceof AcceptedMetadata) {
            $registered = $this->accepted->register(new AcceptedMetadata(
                Uuid::v7(),
                $tenant,
                $serviceProvider->entityId,
                $document,
                $metadata->validUntil,
                $this->clock->now(),
            ));

            return $registered
                ? MetadataRefreshment::registered($serviceProvider->entityId)
                : MetadataRefreshment::registeredMeanwhile($serviceProvider->entityId);
        }
        if ($accepted->holds($document)) {
            return MetadataRefreshment::unchanged($serviceProvider->entityId);
        }
        $accepted->replaceWith($metadata, $document, $this->clock->now());
        $this->accepted->save($accepted);

        return MetadataRefreshment::refreshed($serviceProvider->entityId);
    }

    /**
     * Section 6.2 steps 3 to 5.
     *
     * @throws MetadataRefusedException
     */
    private function read(ServiceProvider $serviceProvider, string $document): ServiceProviderMetadata
    {
        $metadata = $serviceProvider->readsSigned()
            ? $this->reader->readSigned($document, $serviceProvider->metadataSigners)
            : $this->reader->readTrusted($document);
        if ($metadata->entityId !== $serviceProvider->entityId) {
            throw new MetadataRefusedException('The metadata name another entity than the service provider declared (spec/saml.md S-5).');
        }
        if ($serviceProvider->encryptAssertions && $metadata->encryptionCertificates === []) {
            throw new MetadataRefusedException('The service provider asks for encrypted assertions and its metadata hold no key for encryption (spec/saml.md S-7).');
        }
        if ($metadata->signingCertificates === [] && AuthnRequestSigning::of($serviceProvider, $metadata)->required) {
            throw new MetadataRefusedException('The requests of the service provider need a signature and its metadata hold no key for signing (spec/saml.md S-11).');
        }

        return $metadata;
    }
}
