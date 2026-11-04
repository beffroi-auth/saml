<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Metadata;

final readonly class IdentityProviderEndpoints
{
    public function __construct(
        public string $metadata,
        public string $singleSignOn,
        public string $singleLogout,
    ) {
    }
}
