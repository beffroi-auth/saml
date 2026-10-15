<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleLogout;

use Beffroi\Core\Domain\Session\AuthenticationSession;

/**
 * A chain written, to be resumed by its reference once the page of Front-Channel Logout 1.0 for its sessions is shown
 * (spec/saml.md S-35, section 6.6 step 1): the reference in the clear, which only the provider's own pages carry, and
 * the sessions that page is about.
 */
final readonly class LogoutChainStarted
{
    /**
     * @param list<AuthenticationSession> $sessions
     */
    public function __construct(
        public string $reference,
        public array $sessions,
    ) {
    }
}
