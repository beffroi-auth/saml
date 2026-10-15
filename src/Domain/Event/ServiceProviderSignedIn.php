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
 * Single sign-on answered a service provider with an assertion written from a session of the core (spec/saml.md S-26,
 * section 6.4 step 7): the session by its ID, the SessionIndex of the assertion, and the service provider by its entity
 * ID, so that each service provider's part in the session is recorded asynchronously for the logout the identity
 * provider starts (issue #735). It names the person by the subject their account carries, never by the NameID the
 * service provider was given.
 */
final readonly class ServiceProviderSignedIn implements ConcernsAPersonInterface
{
    /**
     * The name of the act, which is what the journal writes down (issue #454).
     */
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
