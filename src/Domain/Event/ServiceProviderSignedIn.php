<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Event;

use Beffroi\Core\Domain\Event\ConcernsAPersonInterface;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Domain\Session\RequestContext;
use Beffroi\Core\Domain\Tenant\Tenant;
use DateTimeImmutable;
use Symfony\Component\Uid\Uuid;

/**
 * spec/saml.md S-26. It names the person by the subject their account carries, never by the NameID the service
 * provider was given.
 */
final readonly class ServiceProviderSignedIn implements ConcernsAPersonInterface
{
    public const string NAME = 'saml.service_provider.signed_in';

    public function __construct(
        public DateTimeImmutable $occurredAt,
        public Tenant $tenant,
        public Uuid $sessionId,
        public string $serviceProvider,
        public Subject $subject,
        public RequestContext $context,
    ) {
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function subject(): Subject
    {
        return $this->subject;
    }
}
