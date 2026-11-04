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
 * spec/saml.md S-39, S-65, section 6.9 step 4. Unsigned, as the metadata of the identity provider are.
 */
final readonly class ModelServiceProviderMetadataWriter implements ServiceProviderMetadataWriterInterface
{
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
                    array_map(static fn (Certificate $certificate): string => $certificate->base64, $description->encryptionCertificates),
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
