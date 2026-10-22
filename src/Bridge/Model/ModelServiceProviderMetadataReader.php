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
 * The metadata of a service provider read by saml2-model's MetadataReader, through MetadataDocumentReader
 * (spec/saml.md section 6.2 steps 3 and 4): readTrusted() for a document its channel vouches for, readSigned() for one
 * signed under the certificates a declaration pins, which then carries a validUntil and is held to the document
 * accepted (S-6), each saying which of the two read it; each, and the reading back of the accepted document, refuses a
 * document without a service provider role and an endpoint the identity provider sends a browser to that is not https
 * on a host (S-11).
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
     * The accepted document of a service provider read back once (spec/saml.md section 6.3 step 1), with readTrusted(),
     * the channel being its own sealed store: what the signature of its requests needs, and the model's role, which
     * validates them and holds the assertion consumer services an answer goes to (S-10).
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
     * S-11: every endpoint of the role the identity provider sends a browser to, the Location of each
     * md:AssertionConsumerService and the Location and the ResponseLocation of each md:SingleLogoutService the model
     * kept, is an https URL on a host (EndpointLocation), at every reading, the reading back of the accepted document
     * among them; the refusal names the endpoint and never its value (M-16).
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
     * @param bool $readSigned whether the document was verified under the certificates a declaration pins (S-6)
     *
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
