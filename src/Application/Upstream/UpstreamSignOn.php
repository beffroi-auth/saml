<?php

declare(strict_types=1);

namespace Beffroi\Saml\Application\Upstream;

use Beffroi\Core\Domain\Encoding\Base64Url;
use function array_unique;
use function array_values;
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
 * (S-49), carrying the address the person gave the login page to a provider that reads one (S-68). Which interaction
 * it serves, where it is remembered and which address was given are the bundle's: this package knows no authorization
 * request (section 2).
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
     * @param string|null $address the address the discovery of the login page was given for the login this sign-on
     *                             serves, as it was given; null when it was given none (S-68)
     *
     * @throws UpstreamSignOnRefusedException when the tenant declares no such provider, or when the request cannot be
     *                                        sent to it
     * @throws KeyNotFoundException when the tenant holds no active SAML key
     * @throws KmsUnavailableException when the KMS does not answer to open it
     */
    public function start(Tenant $tenant, string $identityProvider, bool $forceAuthn, ?string $address = null): SentAuthnRequest
    {
        $provider = $this->providers->find($tenant, $identityProvider);
        if ($provider === null) {
            throw new UpstreamSignOnRefusedException('The identity provider is none this tenant declares (spec/saml.md S-48).');
        }

        return $this->sender->send($tenant, new UpstreamAuthnRequest(
            $identityProvider,
            $this->endpoints->locate($tenant),
            $forceAuthn,
            Base64Url::encode(random_bytes(self::REFERENCE_BYTES)),
            $this->clock->now(),
            $provider->addressHint($address),
        ));
    }

    /**
     * Where a sign-on of the tenant may send a browser (S-61): the single sign-on service each provider it declares
     * would be sent a request at, in the order of the declarations, each once; a provider a sign-on would refuse, with
     * no accepted document or one the reading back refuses, sends a browser nowhere and is left out.
     *
     * @return list<string>
     */
    public function destinations(Tenant $tenant): array
    {
        $destinations = [];
        foreach ($this->providers->of($tenant) as $provider) {
            try {
                $destinations[] = $this->sender->destination($tenant, $provider->entityId);
            } catch (UpstreamSignOnRefusedException) {
                // the sign-on of that provider is refused before the browser leaves (S-48)
            }
        }

        return array_values(array_unique($destinations));
    }
}
