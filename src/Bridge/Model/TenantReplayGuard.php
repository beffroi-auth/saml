<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Port\ReplayStoreInterface;
use Beffroi\Saml2\Model\Port\ReplayGuardInterface;
use DateTimeImmutable;

/**
 * The replay port of saml2-model (model.md section 5.2, M-11) over the store of the application, for the assertions and the
 * logout messages of one tenant (spec/saml.md S-23, S-53): the validator of a message received for that tenant is
 * handed it, so that what the model remembers is remembered under the tenant every row of the store carries.
 */
final readonly class TenantReplayGuard implements ReplayGuardInterface
{
    public function __construct(
        private ReplayStoreInterface $store,
        private Tenant $tenant,
    ) {
    }

    public function remember(string $issuer, string $id, DateTimeImmutable $expiresAt): bool
    {
        return $this->store->remember($this->tenant, $issuer, $id, $expiresAt);
    }
}
