<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\SingleLogout\LogoutChain;

/**
 * The chains of logout the identity provider plays (spec/saml.md S-32), the application's: one store for every worker of
 * the deployment, since the next request of the browser may reach another one.
 */
interface LogoutChainRepositoryInterface
{
    /**
     * Written under its reference, the chains past their ten minutes deleted first.
     */
    public function save(LogoutChain $chain): void;

    /**
     * The chain of the tenant written under the SHA-256 of $reference, open or not.
     */
    public function ofReference(Tenant $tenant, string $reference): ?LogoutChain;

    /**
     * The chain of the tenant that waits for the answer of the request $requestId, open or not.
     */
    public function awaiting(Tenant $tenant, string $requestId): ?LogoutChain;

    /**
     * The chain deleted as it was found, its reference and its outstanding request unchanged: true for the one request
     * that deleted it, false for every other.
     */
    public function take(LogoutChain $chain): bool;
}
