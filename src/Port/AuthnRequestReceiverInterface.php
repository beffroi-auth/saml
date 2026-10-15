<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Saml\Domain\SingleSignOn\SignOnRequest;
use Beffroi\Saml\Exception\SignOnRefusedException;

/**
 * An authentication request received at the single sign-on service of a tenant, decoded by its binding and validated
 * by the model under the signature its service provider needs (spec/saml.md section 6.3), at the URL the metadata of
 * the tenant publish (section 6.8). What the bundle hands it is what bindings.md section 6.8 names, and nothing else.
 */
interface AuthnRequestReceiverInterface
{
    /**
     * @param string $queryString the raw query string, QUERY_STRING as the request carried it
     *
     * @throws SignOnRefusedException when the binding, the model or the declaration refuse it: no SAML answer
     */
    public function redirect(Tenant $tenant, string $queryString): SignOnRequest;

    /**
     * @param array<array-key, mixed> $fields the fields of an application/x-www-form-urlencoded body
     *
     * @throws SignOnRefusedException
     */
    public function post(Tenant $tenant, array $fields): SignOnRequest;
}
