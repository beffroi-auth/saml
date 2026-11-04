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
 * spec/saml.md section 6.11, S-48, S-49, S-50, S-68
 */
final readonly class UpstreamSignOn
{
    /**
     * S-50: 43 characters of base64url, within the 80 bytes of a RelayState.
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
     * @param string|null $address the address the login page was given, as it was given (S-68)
     *
     * @throws UpstreamSignOnRefusedException
     * @throws KeyNotFoundException
     * @throws KmsUnavailableException
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
     * S-61
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
                // A provider whose sign-on would be refused before the browser leaves is left out (S-48).
            }
        }

        return array_values(array_unique($destinations));
    }
}
