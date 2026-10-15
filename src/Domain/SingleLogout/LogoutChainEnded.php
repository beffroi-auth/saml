<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleLogout;

/**
 * Nothing left to tell, and nobody to answer (spec/saml.md S-34): where the browser goes, the URL the starter of the
 * chain named, or null for the page that says it is signed out.
 */
final readonly class LogoutChainEnded
{
    public function __construct(
        public ?string $continueTo,
    ) {
    }
}
