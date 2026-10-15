<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleSignOn;

use DateTimeImmutable;

/**
 * What a failure is written from (spec/saml.md section 6.4 steps 4 and 7): the entity ID of the identity provider, the
 * request it answers, its status and the instant it is issued. It carries no assertion (Profiles §4.1.4.2).
 */
final readonly class SignOnFailure
{
    public function __construct(
        public string $identityProvider,
        public SignOnRequest $request,
        public SignOnStatus $status,
        public DateTimeImmutable $issuedAt,
    ) {
    }
}
