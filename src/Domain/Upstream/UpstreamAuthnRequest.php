<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Upstream;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\Metadata\ServiceProviderEndpoints;
use DateTimeImmutable;
use function sprintf;
use function strlen;

/**
 * What the AuthnRequest the service provider of a tenant sends an upstream identity provider is written from
 * (spec/saml.md S-48, section 6.11 step 3): the entity ID of that provider, the endpoints of the service provider, its
 * entity ID the Issuer and its assertion consumer service where the response goes; whether the request forces a login
 * (S-49); its RelayState, the reference of S-50, never empty and within the 80 bytes of SAML Bindings §3.4.3 and
 * §3.5.3; the instant it is issued at.
 */
final readonly class UpstreamAuthnRequest
{
    /**
     * SAML Bindings §3.4.3, §3.5.3: a RelayState "MUST NOT exceed 80 bytes in length" (section 7).
     */
    public const int MAX_RELAY_STATE_BYTES = 80;

    /**
     * @throws InvalidArgumentException when the RelayState is empty or longer than 80 bytes, a programming error
     */
    public function __construct(
        public string $identityProvider,
        public ServiceProviderEndpoints $serviceProvider,
        public bool $forceAuthn,
        public string $relayState,
        public DateTimeImmutable $issuedAt,
    ) {
        if ($relayState === '' || strlen($relayState) > self::MAX_RELAY_STATE_BYTES) {
            throw new InvalidArgumentException(sprintf(
                'The RelayState of a request to an upstream identity provider is a reference of 1 to %d bytes (spec/saml.md S-50).',
                self::MAX_RELAY_STATE_BYTES,
            ));
        }
    }
}
