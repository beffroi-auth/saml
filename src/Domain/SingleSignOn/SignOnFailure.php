<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleSignOn;

use DateTimeImmutable;

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
