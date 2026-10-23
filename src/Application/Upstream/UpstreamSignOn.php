<?php

declare(strict_types=1);

namespace Beffroi\Saml\Application\Upstream;

use Beffroi\Core\Domain\Encoding\Base64Url;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Saml\Domain\Upstream\SentAuthnRequest;
use Beffroi\Saml\Domain\Upstream\UpstreamAuthnRequest;
use Beffroi\Saml\Exception\UpstreamSignOnRefusedException;
use Beffroi\Saml\Port\AuthnRequestSenderInterface;
use Beffroi\Saml\Port\ServiceProviderEndpointsInterface;
use Beffroi\Saml\Port\UpstreamIdentityProvidersInterface;
use Psr\Clock\ClockInterface;
use function random_bytes;

/**
 * A sign-on of the service provider of a tenant at one of its upstream identity providers started (spec/saml.md section
 * 6.11): the provider one the tenant declares (S-48), the reference the request is remembered under drawn from
 * random_bytes() (S-50), and the AuthnRequest sent, forcing a login when the bundle says the client asked for one
 * (S-49). Which interaction it serves, and where it is remembered, are the bundle's: this package knows no
 * authorization request (section 2).
 */
final readonly class UpstreamSignOn
{
    /**
     * S-50: the reference is 32 bytes, 43 characters of base64url, within the 80 bytes of a RelayState.
     */
    private const int REFERENCE_BYTES = 32;

    public function __construct(
        private UpstreamIdentityProvidersInterface $providers,
        private ServiceProviderEndpointsInterface $endpoints,
        private AuthnRequestSenderInterface $sender,
        private ClockInterface $clock,
    ) {
    }

    /**
     * @param string $identityProvider the entity ID of the provider, as the route was given it
     * @param bool $forceAuthn whether the request forces a login (S-49)
     *
     * @throws UpstreamSignOnRefusedException when the tenant declares no such provider, or when the request cannot be
     *                                        sent to it
     * @throws KeyNotFoundException when the tenant holds no active SAML key
     * @throws KmsUnavailableException when the KMS does not answer to open it
     */
    public function start(Tenant $tenant, string $identityProvider, bool $forceAuthn): SentAuthnRequest
    {
        if ($this->providers->find($tenant, $identityProvider) === null) {
            throw new UpstreamSignOnRefusedException('The identity provider is none this tenant declares (spec/saml.md S-48).');
        }

        return $this->sender->send($tenant, new UpstreamAuthnRequest(
            $identityProvider,
            $this->endpoints->locate($tenant),
            $forceAuthn,
            Base64Url::encode(random_bytes(self::REFERENCE_BYTES)),
            $this->clock->now(),
        ));
    }
}
