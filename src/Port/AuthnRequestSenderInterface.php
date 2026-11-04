<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Saml\Domain\Upstream\SentAuthnRequest;
use Beffroi\Saml\Domain\Upstream\UpstreamAuthnRequest;
use Beffroi\Saml\Exception\UpstreamSignOnRefusedException;

interface AuthnRequestSenderInterface
{
    /**
     * @throws UpstreamSignOnRefusedException
     * @throws KeyNotFoundException
     * @throws KmsUnavailableException
     */
    public function send(Tenant $tenant, UpstreamAuthnRequest $request): SentAuthnRequest;

    /**
     * The Location of the single sign-on service send() writes to, by the same rule (S-48).
     *
     * @throws UpstreamSignOnRefusedException
     */
    public function destination(Tenant $tenant, string $identityProvider): string;
}
