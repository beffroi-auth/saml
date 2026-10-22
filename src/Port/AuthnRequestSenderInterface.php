<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Saml\Domain\Upstream\SentAuthnRequest;
use Beffroi\Saml\Domain\Upstream\UpstreamAuthnRequest;
use Beffroi\Saml\Exception\UpstreamSignOnRefusedException;

/**
 * The AuthnRequest the service provider of a tenant sends an upstream identity provider (spec/saml.md S-48, section
 * 6.11 steps 4 and 5): written to a single sign-on service of the accepted document of that provider, read back when it
 * is written, and signed by the active SAML key of the tenant.
 */
interface AuthnRequestSenderInterface
{
    /**
     * @throws UpstreamSignOnRefusedException when the provider has no accepted document, when the reading back refuses
     *                                        its document, or when the model, the binding or Dsig refuses to write the
     *                                        request
     * @throws KeyNotFoundException when the tenant holds no active SAML key
     * @throws KmsUnavailableException when the KMS does not answer to open it
     */
    public function send(Tenant $tenant, UpstreamAuthnRequest $request): SentAuthnRequest;

    /**
     * The Location of the single sign-on service a request to that provider is written to, by the rule send() writes it
     * by (S-48): what the page that starts a sign-on names in its "form-action" (S-61).
     *
     * @throws UpstreamSignOnRefusedException when the provider has no accepted document, or the reading back refuses it
     */
    public function destination(Tenant $tenant, string $identityProvider): string;
}
