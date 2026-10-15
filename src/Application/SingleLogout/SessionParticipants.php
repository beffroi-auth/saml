<?php

declare(strict_types=1);

namespace Beffroi\Saml\Application\SingleLogout;

use Beffroi\Core\Port\AuthenticationSessionRepositoryInterface;
use Beffroi\Saml\Domain\Event\ServiceProviderSignedIn;
use Beffroi\Saml\Domain\SingleLogout\SessionParticipation;
use Beffroi\Saml\Port\SessionParticipationRepositoryInterface;
use Symfony\Component\Uid\Uuid;

/**
 * Each service provider's part in a session of the core, recorded from the event single sign-on announces (spec/saml.md
 * S-26): one row per session and service provider, for a session that still exists, which the logout the identity
 * provider starts reads (issue #735).
 */
final readonly class SessionParticipants
{
    public function __construct(
        private AuthenticationSessionRepositoryInterface $sessions,
        private SessionParticipationRepositoryInterface $participations,
    ) {
    }

    public function signedIn(ServiceProviderSignedIn $event): void
    {
        $session = $this->sessions->find($event->sessionId);
        if ($session === null || ! $session->tenant->equals($event->tenant)) {
            return;
        }
        $this->participations->record(new SessionParticipation(
            Uuid::v7(),
            $event->tenant,
            $session,
            $event->serviceProvider,
            $event->occurredAt,
        ));
    }
}
