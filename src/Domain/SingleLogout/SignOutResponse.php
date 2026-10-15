<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleLogout;

use DateTimeImmutable;

/**
 * What the answer to a LogoutRequest is written from (spec/saml.md section 6.5 step 4, S-27): the entity ID of the
 * identity provider, the request it answers, its status and the instant it is issued.
 */
final readonly class SignOutResponse
{
    public function __construct(
        public string $identityProvider,
        public SignOutRequest $request,
        public SignOutStatus $status,
        public DateTimeImmutable $issuedAt,
    ) {
    }
}
