<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\SingleLogout\LogoutChain;

/**
 * One store for every worker of the deployment: the next request of the browser may reach another one.
 */
interface LogoutChainRepositoryInterface
{
    /**
     * The chains past their ten minutes are deleted first.
     */
    public function save(LogoutChain $chain): void;

    /**
     * Found by the SHA-256 of $reference, open or not.
     */
    public function ofReference(Tenant $tenant, string $reference): ?LogoutChain;

    /**
     * The chain that waits for the answer of $requestId, open or not.
     */
    public function awaiting(Tenant $tenant, string $requestId): ?LogoutChain;

    /**
     * Deletes the chain only as it was found, its reference and its outstanding request unchanged: true for the one
     * request that deleted it.
     */
    public function take(LogoutChain $chain): bool;
}
