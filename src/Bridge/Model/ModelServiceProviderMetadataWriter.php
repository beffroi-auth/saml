<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use function array_map;
use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml\Domain\Metadata\ServiceProviderDescription;
use Beffroi\Saml\Port\ServiceProviderMetadataWriterInterface;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoint;
use Beffroi\Saml2\Model\Metadata\IndexedEndpoints;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Writing\MetadataWriter;
use Beffroi\Xml\Core\Serializer;

/**
 * The metadata of the service provider of a tenant written by saml2-model's MetadataWriter and serialized by Core
 * (spec/saml.md S-39, section 6.9 step 4): one md:EntityDescriptor whose entity ID is the one of S-38, one
 * md:SPSSODescriptor that says its requests are signed and wants the assertions it receives signed, a signing
 * certificate per SAML key in service, and one assertion consumer service on HTTP-POST, of index 0; the cacheDuration
 * of S-12 on the md:EntityDescriptor.
 *
 * Unsigned, as the metadata of the identity provider are (section 6.1 step 5). No validUntil, no single logout service
 * (Single Logout with an upstream identity provider is out of sub-spike 9d, section 11), no key for encryption (issue
 * #787) and no NameID format, the format the service provider asks for being the NameIDPolicy of its request (issue
 * #783).
 */
final readonly class ModelServiceProviderMetadataWriter implements ServiceProviderMetadataWriterInterface
{
    /**
     * The index of the one assertion consumer service, an xs:unsignedShort the reader requires (SAML Metadata §2.2.3).
     */
    private const int ASSERTION_CONSUMER_SERVICE_INDEX = 0;

    public function __construct(
        private MetadataWriter $writer = new MetadataWriter(),
        private Serializer $serializer = new Serializer(),
    ) {
    }

    public function write(ServiceProviderDescription $description): string
    {
        $entityId = $description->entityId();

        return $this->serializer->serialize($this->writer->write(
            new EntityDescriptor(
                $entityId,
                null,
                null,
                new ServiceProvider(
                    $entityId,
                    array_map(static fn (Certificate $certificate): string => $certificate->base64, $description->signingCertificates),
                    [],
                    new IndexedEndpoints([
                        new IndexedEndpoint(Binding::HttpPost, $description->endpoints->assertionConsumerService, self::ASSERTION_CONSUMER_SERVICE_INDEX),
                    ]),
                    authnRequestsSigned: true,
                    wantAssertionsSigned: true,
                ),
                $description->cacheDuration,
            ),
            null,
        ));
    }
}
