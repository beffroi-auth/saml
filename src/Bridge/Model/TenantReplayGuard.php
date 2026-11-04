<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Port\ReplayStoreInterface;
use Beffroi\Saml2\Model\Port\ReplayGuardInterface;
use DateTimeImmutable;

/**
 * model.md M-11, spec/saml.md S-23, S-53
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
