<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use DateTimeImmutable;

/**
 * Shared by every worker and atomic: two concurrent calls with the same message answer true once.
 */
interface ReplayStoreInterface
{
    /**
     * @return bool true when the message had not been seen under $tenant and is now remembered
     */
    public function remember(Tenant $tenant, string $issuer, string $id, DateTimeImmutable $expiresAt): bool;
}
