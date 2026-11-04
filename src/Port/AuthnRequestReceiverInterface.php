<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\SingleSignOn\SignOnRequest;
use Beffroi\Saml\Exception\SignOnRefusedException;

interface AuthnRequestReceiverInterface
{
    /**
     * @param string $queryString the raw query string, QUERY_STRING as the request carried it
     *
     * @throws SignOnRefusedException
     */
    public function redirect(Tenant $tenant, string $queryString): SignOnRequest;

    /**
     * @param array<array-key, mixed> $fields
     *
     * @throws SignOnRefusedException
     */
    public function post(Tenant $tenant, array $fields): SignOnRequest;
}
