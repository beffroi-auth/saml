<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleLogout;

/**
 * The LogoutResponse of the outstanding request of a chain, validated (spec/saml.md S-33): the chain it answers, as it
 * was found; whether its top-level status is Success, another status being an answer, which the chain counts; and the
 * secret of the browser that carried it, the one the chain is bound to (S-32).
 */
final readonly class SignOutAnswer
{
    public function __construct(
        public LogoutChain $chain,
        public bool $success,
        public LogoutChainSecret $secret,
    ) {
    }
}
