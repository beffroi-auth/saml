<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\ServiceProvider\ServiceProvider;

interface ServiceProvidersInterface
{
    /**
     * @return list<ServiceProvider> in the order of the declaration
     */
    public function of(Tenant $tenant): array;

    /**
     * The entity ID is compared exactly.
     */
    public function find(Tenant $tenant, string $entityId): ?ServiceProvider;
}
