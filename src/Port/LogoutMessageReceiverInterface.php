<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\SingleLogout\LogoutChainSecret;
use Beffroi\Saml\Domain\SingleLogout\SignOutAnswer;
use Beffroi\Saml\Domain\SingleLogout\SignOutRequest;
use Beffroi\Saml\Exception\LogoutRefusedException;

/**
 * A LogoutResponse is validated under the accepted metadata of the service provider the request of its chain went
 * to, never of the one its Issuer names (spec/saml.md section 6.6 step 4, S-33).
 */
interface LogoutMessageReceiverInterface
{
    /**
     * From the raw query string (section 6.8).
     *
     * @param LogoutChainSecret|null $secret a LogoutResponse is read only for a chain bound to it (S-32, S-33)
     *
     * @throws LogoutRefusedException
     */
    public function redirect(Tenant $tenant, string $queryString, ?LogoutChainSecret $secret): SignOutRequest|SignOutAnswer;

    /**
     * @param array<array-key, mixed> $fields
     *
     * @throws LogoutRefusedException
     */
    public function post(Tenant $tenant, array $fields, ?LogoutChainSecret $secret): SignOutRequest|SignOutAnswer;
}
