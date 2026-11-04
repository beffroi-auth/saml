<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Upstream;

use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\Metadata\ServiceProviderEndpoints;
use DateTimeImmutable;
use function sprintf;
use function strlen;

final readonly class UpstreamAuthnRequest
{
    /**
     * SAML Bindings §3.4.3, §3.5.3
     */
    public const int MAX_RELAY_STATE_BYTES = 80;

    /**
     * @throws InvalidArgumentException when the RelayState is empty or longer than 80 bytes
     */
    public function __construct(
        public string $identityProvider,
        public ServiceProviderEndpoints $serviceProvider,
        public bool $forceAuthn,
        public string $relayState,
        public DateTimeImmutable $issuedAt,
        public ?AddressHint $addressHint = null,
    ) {
        if ($relayState === '' || strlen($relayState) > self::MAX_RELAY_STATE_BYTES) {
            throw new InvalidArgumentException(sprintf(
                'The RelayState of a request to an upstream identity provider is a reference of 1 to %d bytes (spec/saml.md S-50).',
                self::MAX_RELAY_STATE_BYTES,
            ));
        }
    }
}
