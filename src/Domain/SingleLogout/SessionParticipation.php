<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleLogout;

use Beffroi\Core\Domain\PersonalData\ClassifiedFieldsInterface;
use Beffroi\Core\Domain\PersonalData\FieldClassificationInterface;
use Beffroi\Core\Domain\PersonalData\NoPersonalDatum;
use Beffroi\Core\Domain\PersonalData\Reason;
use Beffroi\Core\Domain\Session\AuthenticationSession;
use Beffroi\Core\Domain\Tenant\Tenant;
use DateTimeImmutable;
use Symfony\Component\Uid\Uuid;

/**
 * A service provider's part in a session of the core (spec/saml.md S-26): the session an assertion was written from,
 * the service provider it went to, and the instant of its first sign-on there. One per session and service provider,
 * written once whatever the number of sign-ons, deleted with the session; what the logout the identity provider starts
 * reads to tell each service provider of an ended session (issue #735).
 */
final readonly class SessionParticipation implements ClassifiedFieldsInterface
{
    public function __construct(
        public Uuid $id,
        public Tenant $tenant,
        public AuthenticationSession $session,
        public string $serviceProvider,
        public DateTimeImmutable $signedInAt,
    ) {
    }

    /**
     * The service provider names an application, as the client of an authorization code does; the session is joined
     * by its identifier, as the codes join it.
     *
     * @return array<string, FieldClassificationInterface>
     */
    public static function classifiedFields(): array
    {
        return [
            'id' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
            'tenant' => new NoPersonalDatum(Reason::THE_TENANT),
            'session' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
            'serviceProvider' => new NoPersonalDatum('names a service provider, an application and never a person'),
            'signedInAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
        ];
    }
}
