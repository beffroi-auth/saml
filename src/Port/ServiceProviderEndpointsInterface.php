<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\Metadata\ServiceProviderEndpoints;
use LogicException;

/**
 * Where and as whom the service provider of a tenant is served (spec/saml.md S-38, section 6.9 step 3): routing and the
 * setting of the entity ID belong to the integration, which locates the endpoints under the issuer of the tenant and
 * never under what a request carried (S-39).
 */
interface ServiceProviderEndpointsInterface
{
    /**
     * @throws LogicException when the routes are not mounted under the issuer of the tenant: metadata naming
     *                        endpoints nobody serves is not metadata to publish
     * @throws InvalidArgumentException when the entity ID the deployment names is not one, or is the entity ID of the
     *                                  identity provider of the tenant (S-38)
     */
    public function locate(Tenant $tenant): ServiceProviderEndpoints;
}
