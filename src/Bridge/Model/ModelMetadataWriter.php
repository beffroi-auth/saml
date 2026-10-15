<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use Beffroi\Saml\Domain\Metadata\IdentityProviderDescription;
use Beffroi\Saml\Port\MetadataWriterInterface;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Writing\MetadataWriter;
use Beffroi\Xml\Core\Serializer;

/**
 * The metadata of the identity provider of a tenant written by saml2-model's MetadataWriter and serialized by Core
 * (spec/saml.md section 6.1 steps 3 to 5): one md:EntityDescriptor whose entity ID is the URL of the metadata, one
 * md:IDPSSODescriptor holding a signing certificate per key in service, the single sign-on and the single logout
 * services each listed with HTTP-Redirect then HTTP-POST at one URL, the persistent NameID format of S-13, and
 * WantAuthnRequestsSigned as the tenant set it (ModelIdentityProvider), and the cacheDuration of S-12 on the
 * md:EntityDescriptor.
 *
 * Unsigned: the key that would sign it is a key it publishes, so a service provider trusts it by the channel it came
 * through. No validUntil, no encryption certificate: the identity provider decrypts nothing (spec/saml.md section 11).
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
