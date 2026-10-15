<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use function array_map;
use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml\Domain\Metadata\IdentityProviderEndpoints;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;

/**
 * The model's IdentityProvider of a tenant (spec/saml.md sections 6.1 and 6.3): its entity ID, the URL of its
 * metadata; the single sign-on and the single logout services each at one URL, with HTTP-Redirect then HTTP-POST
 * (model.md section 6.9); the persistent NameID format it writes (S-13); and WantAuthnRequestsSigned as it is given,
 * which IdentityProvider's constructor would otherwise default to false. What the metadata publish and what the
 * receiver validates a request against are built here once.
 */
final readonly class ModelIdentityProvider
{
    /**
     * @param list<Certificate> $signingCertificates
     */
    public static function of(IdentityProviderEndpoints $endpoints, array $signingCertificates, bool $wantAuthnRequestsSigned): IdentityProvider
    {
        return new IdentityProvider(
            $endpoints->metadata,
            array_map(static fn (Certificate $certificate): string => $certificate->base64, $signingCertificates),
            [],
            self::bothBindings($endpoints->singleSignOn),
            self::bothBindings($endpoints->singleLogout),
            [NameIdFormat::Persistent],
            $wantAuthnRequestsSigned,
        );
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
