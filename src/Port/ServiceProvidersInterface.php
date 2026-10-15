<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\ServiceProvider\ServiceProvider;

/**
 * The service providers a tenant declares (spec/saml.md S-5, section 5.2).
 */
interface ServiceProvidersInterface
{
    /**
     * @return list<ServiceProvider> in the order of the declaration
     */
    public function of(Tenant $tenant): array;

    /**
     * The service provider of that entity ID, compared exactly, or null when the tenant declares none.
     */
    public function find(Tenant $tenant, string $entityId): ?ServiceProvider;
}
