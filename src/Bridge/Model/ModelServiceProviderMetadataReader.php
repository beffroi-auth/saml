<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use Beffroi\Saml\Domain\ServiceProvider\ServiceProviderMetadata;
use Beffroi\Saml\Exception\MetadataRefusedException;
use Beffroi\Saml\Port\ServiceProviderMetadataReaderInterface;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Psr\Clock\ClockInterface;

/**
 * spec/saml.md section 6.2 steps 3 and 4, S-11
 */
final readonly class ModelServiceProviderMetadataReader implements ServiceProviderMetadataReaderInterface
{
    private MetadataDocumentReader $documents;

    public function __construct(ClockInterface $clock)
    {
        $this->documents = new MetadataDocumentReader($clock);
    }

    public function readTrusted(string $document): ServiceProviderMetadata
    {
        $descriptor = $this->documents->trusted($document);

        return self::metadataOf($descriptor, self::role($descriptor), false);
    }

    public function readSigned(string $document, array $signers): ServiceProviderMetadata
    {
        $descriptor = $this->documents->signed($document, $signers);

        return self::metadataOf($descriptor, self::role($descriptor), true);
    }

    /**
     * Section 6.3 step 1: read with readTrusted(), the channel being the sealed store of the accepted documents.
     *
     * @throws MetadataRefusedException
     */
    public function readAccepted(string $document): ReadServiceProvider
    {
        $descriptor = $this->documents->trusted($document);
        $role = self::role($descriptor);

        return new ReadServiceProvider(self::metadataOf($descriptor, $role, false), $role);
    }

    /**
     * @throws MetadataRefusedException
     */
    private static function role(EntityDescriptor $descriptor): ServiceProvider
    {
        $role =
            $descriptor->serviceProvider ?? throw new MetadataRefusedException('The metadata hold no service provider role of SAML 2.0 (spec/saml.md S-5).');
        self::endpointsOf($role);

        return $role;
    }

    /**
     * S-11: every endpoint the identity provider sends a browser to is an https URL on a host.
     *
     * @throws MetadataRefusedException
     */
    private static function endpointsOf(ServiceProvider $role): void
    {
        foreach ($role->assertionConsumerServices->endpoints as $endpoint) {
            self::location($endpoint->location, 'Location', 'md:AssertionConsumerService');
        }
        foreach ($role->singleLogoutServices as $endpoint) {
            self::location($endpoint->location, 'Location', 'md:SingleLogoutService');
            if ($endpoint->responseLocation !== null) {
                self::location($endpoint->responseLocation, 'ResponseLocation', 'md:SingleLogoutService');
            }
        }
    }

    /**
     * @throws MetadataRefusedException
     */
    private static function location(string $location, string $attribute, string $element): void
    {
        MetadataDocumentReader::assertHttpsOnAHost($location, $attribute, $element, 'the identity provider', 'S-11');
    }

    /**
     * @throws MetadataRefusedException
     */
    private static function metadataOf(EntityDescriptor $descriptor, ServiceProvider $role, bool $readSigned): ServiceProviderMetadata
    {
        return new ServiceProviderMetadata(
            $descriptor->entityId,
            $descriptor->validUntil,
            MetadataDocumentReader::certificates($role->encryptionCertificates),
            $role->authnRequestsSigned,
            MetadataDocumentReader::certificates($role->signingCertificates),
            $readSigned,
        );
    }
}
