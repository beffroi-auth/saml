<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleLogout;

/**
 * The LogoutResponse of the outstanding request of a chain, validated (spec/saml.md S-33): the chain it answers, as it
 * was found, and whether its top-level status is Success; another status is an answer, which the chain counts.
 */
final readonly class SignOutAnswer
{
    public function __construct(
        public LogoutChain $chain,
        public bool $success,
    ) {
    }
}
