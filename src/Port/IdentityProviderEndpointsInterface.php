<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\Metadata\IdentityProviderEndpoints;
use LogicException;

/**
 * Where the identity provider of a tenant is served (spec/saml.md section 6.1 step 3): routing belongs to the
 * integration, which locates the endpoints under the issuer of the tenant and never under what a request carried
 * (S-4).
 */
interface IdentityProviderEndpointsInterface
{
    /**
     * @throws LogicException when the routes are not mounted under the issuer of the tenant: metadata naming
     *                        endpoints nobody serves is not metadata to publish
     */
    public function locate(Tenant $tenant): IdentityProviderEndpoints;
}
