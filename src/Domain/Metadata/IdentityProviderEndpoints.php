<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Metadata;

/**
 * Where the identity provider of a tenant is reached (spec/saml.md section 6.1 step 3): the URL of its metadata, which
 * is its entity ID, and the URL of each of its two services, where both bindings arrive, the method telling them apart.
 * Located under the issuer of the tenant by whoever holds the routes, never read from a request (S-4); the model checks
 * each of them as a URI of M-6 when the metadata is written.
 */
final readonly class IdentityProviderEndpoints
{
    public function __construct(
        public string $metadata,
        public string $singleSignOn,
        public string $singleLogout,
    ) {
    }
}
