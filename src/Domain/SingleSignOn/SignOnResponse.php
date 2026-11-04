<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleSignOn;

use Beffroi\Saml\Domain\Metadata\Certificate;
use DateInterval;
use DateTimeImmutable;
use function sprintf;

final readonly class SignOnResponse
{
    /**
     * Seconds an assertion is valid (S-15).
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

    public function notOnOrAfter(): DateTimeImmutable
    {
        return $this->issuedAt->add(new DateInterval(sprintf('PT%dS', self::VALIDITY)));
    }
}
