<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleLogout;

final readonly class SignOutAnswer
{
    public function __construct(
        public LogoutChain $chain,
        public bool $success,
        public LogoutChainSecret $secret,
    ) {
    }
}
