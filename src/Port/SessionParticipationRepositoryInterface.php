<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Saml\Domain\SingleLogout\SessionParticipation;
use Symfony\Component\Uid\Uuid;

/**
 * Each service provider's part in a session of the core (spec/saml.md S-26), the bundle's.
 */
interface SessionParticipationRepositoryInterface
{
    /**
     * Written once per session and service provider: a second sign-on of the same session to the same service
     * provider leaves the first row as it was, whichever worker writes it.
     */
    public function record(SessionParticipation $participation): void;

    /**
     * The service providers of a session, in the order of their first sign-on, which the logout the identity
     * provider starts tells (issue #735).
     *
     * @return list<SessionParticipation>
     */
    public function ofSession(Uuid $sessionId): array;
}
