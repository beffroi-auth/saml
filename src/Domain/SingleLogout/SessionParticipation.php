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
