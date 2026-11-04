<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleLogout;

use DateTimeImmutable;

final readonly class SignOutResponse
{
    public function __construct(
        public string $identityProvider,
        public LogoutRequester $requester,
        public SignOutStatus $status,
        public DateTimeImmutable $issuedAt,
    ) {
    }
}
