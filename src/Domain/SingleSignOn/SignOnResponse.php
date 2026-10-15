<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleSignOn;

use Beffroi\Saml\Domain\Metadata\Certificate;
use DateInterval;
use DateTimeImmutable;
use function sprintf;

/**
 * What a successful answer to a request is written from (spec/saml.md section 6.4 step 7): the entity ID of the
 * identity provider, its Issuer (S-14); the request, which gives the Destination, the Recipient, the InResponseTo, the
 * Audience and the RelayState; the subject and its attributes; the session, by its ID and its latest proof; the
 * instant it is issued, from which it is valid five minutes (S-15); the certificate the assertion is encrypted for, the
 * first for encryption of the accepted metadata of a service provider that asks for it, null for one that does not
 * (S-19).
 */
final readonly class SignOnResponse
{
    /**
     * How long an assertion is valid, in seconds (S-15, section 7).
     */
    public const int VALIDITY = 300;

    /**
     * @param list<ReleasedAttribute> $attributes
     */
    public function __construct(
        public string $identityProvider,
        public SignOnRequest $request,
        public PersistentNameId $nameId,
        public array $attributes,
        public string $sessionIndex,
        public DateTimeImmutable $authnInstant,
        public DateTimeImmutable $issuedAt,
        public ?Certificate $encryptFor = null,
    ) {
    }

    /**
     * The end of the Conditions and of the bearer confirmation.
     */
    public function notOnOrAfter(): DateTimeImmutable
    {
        return $this->issuedAt->add(new DateInterval(sprintf('PT%dS', self::VALIDITY)));
    }
}
