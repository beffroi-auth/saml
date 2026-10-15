<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\SingleLogout\SignOutRequest;
use Beffroi\Saml\Exception\LogoutRefusedException;

/**
 * A LogoutRequest received at the single logout service of the tenant and accepted (spec/saml.md section 6.5 step 1,
 * S-22, S-23): decoded by the binding, its service provider chosen by its unverified Issuer, validated by saml2-model
 * under the accepted metadata of that provider, remembered by the replay store, and the endpoint of its answer
 * resolved among the single logout services of those metadata (S-27).
 */
interface LogoutRequestReceiverInterface
{
    /**
     * HTTP-Redirect, from the raw query string (section 6.8).
     *
     * @throws LogoutRefusedException when the request is refused: no SAML answer
     */
    public function redirect(Tenant $tenant, string $queryString): SignOutRequest;

    /**
     * HTTP-POST, from the fields of the form (section 6.8).
     *
     * @param array<array-key, mixed> $fields
     *
     * @throws LogoutRefusedException
     */
    public function post(Tenant $tenant, array $fields): SignOutRequest;
}
