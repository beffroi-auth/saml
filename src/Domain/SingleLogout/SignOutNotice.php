<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleLogout;

use DateInterval;
use DateTimeImmutable;
use function sprintf;

final readonly class SignOutNotice
{
    /**
     * Seconds from IssueInstant to NotOnOrAfter: the maxMessageAge of saml2-model.
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
