<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\Metadata\IdentityProviderEndpoints;
use LogicException;

/**
 * Located under the issuer of the tenant, never under what a request carried (spec/saml.md S-4).
 */
interface IdentityProviderEndpointsInterface
{
    /**
     * @throws LogicException when the routes are not mounted under the issuer of the tenant
     */
    public function locate(Tenant $tenant): IdentityProviderEndpoints;
}
