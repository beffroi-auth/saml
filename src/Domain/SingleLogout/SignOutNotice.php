<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleLogout;

use DateInterval;
use DateTimeImmutable;
use function sprintf;

/**
 * What the LogoutRequest the identity provider sends a service provider is written from (spec/saml.md S-31): the
 * entity ID of the tenant, the service provider, the persistent NameID S-13 computes for it and the user of the
 * session, the ID of the session as its SessionIndex, and the instant it is issued. Where it goes is read from the
 * accepted metadata of the service provider when it is written, never from here.
 */
final readonly class SignOutNotice
{
    /**
     * Seconds the request is valid, its NotOnOrAfter after its IssueInstant: the maxMessageAge of saml2-model.
     */
    public const int VALIDITY = 300;

    public function __construct(
        public string $identityProvider,
        public string $serviceProvider,
        public string $nameId,
        public string $sessionIndex,
        public DateTimeImmutable $issuedAt,
    ) {
    }

    public function notOnOrAfter(): DateTimeImmutable
    {
        return $this->issuedAt->add(new DateInterval(sprintf('PT%dS', self::VALIDITY)));
    }
}
