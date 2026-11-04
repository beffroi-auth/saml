<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Saml\Domain\SingleLogout\SessionParticipation;
use Symfony\Component\Uid\Uuid;

interface SessionParticipationRepositoryInterface
{
    /**
     * Once per session and service provider: a second sign-on leaves the first row as it was, whichever worker
     * writes it.
     */
    public function record(SessionParticipation $participation): void;

    /**
     * @return list<SessionParticipation> in the order of their first sign-on
     */
    public function ofSession(Uuid $sessionId): array;
}
