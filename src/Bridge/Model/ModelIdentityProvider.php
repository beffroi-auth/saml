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
