<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\Upstream\UpstreamIdentityProvider;

/**
 * The upstream identity providers a tenant declares (spec/saml.md S-42, section 5.7): what the stories that read an
 * assertion of one of them are handed (S-45).
 */
interface UpstreamIdentityProvidersInterface
{
    /**
     * @return list<UpstreamIdentityProvider> in the order of the declaration
     */
    public function of(Tenant $tenant): array;

    /**
     * The upstream identity provider of that entity ID, compared exactly, or null when the tenant declares none.
     */
    public function find(Tenant $tenant, string $entityId): ?UpstreamIdentityProvider;
}
