<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleLogout;

use Beffroi\Core\Domain\Session\AuthenticationSession;

final readonly class LogoutChainStarted
{
    /**
     * @param list<AuthenticationSession> $sessions
     */
    public function __construct(
        public string $reference,
        public LogoutChainSecret $secret,
        public array $sessions,
    ) {
    }
}
