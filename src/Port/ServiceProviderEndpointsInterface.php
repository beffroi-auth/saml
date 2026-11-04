<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\Metadata\ServiceProviderEndpoints;
use LogicException;

/**
 * Located under the issuer of the tenant, never under what a request carried (spec/saml.md S-39).
 */
interface ServiceProviderEndpointsInterface
{
    /**
     * @throws LogicException when the routes are not mounted under the issuer of the tenant
     * @throws InvalidArgumentException when the entity ID the deployment names is not one, or is the one of the
     *                                  identity provider of the tenant (S-38)
     */
    public function locate(Tenant $tenant): ServiceProviderEndpoints;
}
