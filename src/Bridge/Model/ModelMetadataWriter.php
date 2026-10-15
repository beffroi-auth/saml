<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml\Domain\Metadata\IdentityProviderDescription;
use Beffroi\Saml\Port\MetadataWriterInterface;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Writing\MetadataWriter;
use Beffroi\Xml\Core\Serializer;
use function array_map;

/**
 * The metadata of the identity provider of a tenant written by saml2-model's MetadataWriter and serialized by Core
 * (spec/saml.md section 6.1 steps 3 to 5): one md:EntityDescriptor whose entity ID is the URL of the metadata, one
 * md:IDPSSODescriptor holding a signing certificate per key in service, the single sign-on and the single logout
 * services each listed with HTTP-Redirect then HTTP-POST at one URL, and WantAuthnRequestsSigned as the tenant set it,
 * which IdentityProvider's constructor would otherwise default to false (model.md section 6.9), and the cacheDuration
 * of S-12 on the md:EntityDescriptor.
 *
 * Unsigned: the key that would sign it is a key it publishes, so a service provider trusts it by the channel it came
 * through. No validUntil, no encryption certificate (issue #733) and no NameIDFormat (issue #731).
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
        $entityId = $description->entityId();
        $endpoints = $description->endpoints;

        return $this->serializer->serialize($this->writer->write(
            new EntityDescriptor(
                $entityId,
                null,
                new IdentityProvider(
                    $entityId,
                    array_map(static fn (Certificate $certificate): string => $certificate->base64, $description->signingCertificates),
                    [],
                    self::bothBindings($endpoints->singleSignOn),
                    self::bothBindings($endpoints->singleLogout),
                    wantAuthnRequestsSigned: $description->wantAuthnRequestsSigned,
                ),
                cacheDuration: $description->cacheDuration,
            ),
            null,
        ));
    }

    /**
     * HTTP-Redirect then HTTP-POST at the same URL (model.md section 6.9): a broker configured from the metadata posts
     * its requests, and one that redirects finds its binding too.
     *
     * @return list<Endpoint>
     */
    private static function bothBindings(string $location): array
    {
        return [
            new Endpoint(Binding::HttpRedirect, $location),
            new Endpoint(Binding::HttpPost, $location),
        ];
    }
}
