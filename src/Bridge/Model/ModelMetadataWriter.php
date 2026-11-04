<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use Beffroi\Saml\Domain\Metadata\IdentityProviderDescription;
use Beffroi\Saml\Port\MetadataWriterInterface;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Writing\MetadataWriter;
use Beffroi\Xml\Core\Serializer;

/**
 * spec/saml.md section 6.1 steps 3 to 5. Unsigned: the key that would sign it is a key it publishes, so a service
 * provider trusts it by the channel it came through.
 */
final readonly class ModelMetadataWriter implements MetadataWriterInterface
{
    public function __construct(
        private MetadataWriter $writer = new MetadataWriter(),
        private Serializer $serializer = new Serializer(),
    ) {
    }

    public function write(IdentityProviderDescription $description): string
    {
        return $this->serializer->serialize($this->writer->write(
            new EntityDescriptor(
                $description->entityId(),
                null,
                ModelIdentityProvider::of($description->endpoints, $description->signingCertificates, $description->wantAuthnRequestsSigned),
                cacheDuration: $description->cacheDuration,
            ),
            null,
        ));
    }
}
