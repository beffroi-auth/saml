<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\SingleLogout\SignOutAnswer;
use Beffroi\Saml\Domain\SingleLogout\SignOutRequest;
use Beffroi\Saml\Exception\LogoutRefusedException;

/**
 * A logout message received at the single logout service of the tenant and accepted: a LogoutRequest of a service
 * provider (spec/saml.md section 6.5 step 1, S-22, S-23), decoded by the binding, its service provider chosen by its
 * unverified Issuer, validated by saml2-model under the accepted metadata of that provider, remembered by the replay
 * store, the endpoint of its answer resolved among the single logout services of those metadata (S-27); or the
 * LogoutResponse of the request a chain waits for (section 6.6 step 4, S-33), validated under the accepted metadata of
 * the service provider that request went to.
 */
interface LogoutMessageReceiverInterface
{
    /**
     * HTTP-Redirect, from the raw query string (section 6.8).
     *
     * @throws LogoutRefusedException when the message is refused: no SAML answer
     */
    public function redirect(Tenant $tenant, string $queryString): SignOutRequest|SignOutAnswer;

    /**
     * HTTP-POST, from the fields of the form (section 6.8).
     *
     * @param array<array-key, mixed> $fields
     *
     * @throws LogoutRefusedException
     */
    public function post(Tenant $tenant, array $fields): SignOutRequest|SignOutAnswer;
}
