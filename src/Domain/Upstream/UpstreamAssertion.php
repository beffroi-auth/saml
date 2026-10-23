<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Upstream;

use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use DateTimeImmutable;

/**
 * What the service provider of a tenant makes of an assertion of an upstream identity provider it took (spec/saml.md
 * S-55 to S-57): the declaration of that provider; the subject of the person at it; the address, its domain written as
 * its A-label; the claims of the profile it said, by the names of OIDC Core §5.1, those of the core's provider; the
 * telephone number apart, which is none of them; the values of the groups attribute, which the declaration maps; the
 * AuthnInstant, the auth_time of the session; the methods of RFC 8176 it proves; and the SessionNotOnOrAfter, after
 * which the session it opens is over (S-57).
 */
final readonly class UpstreamAssertion
{
    /**
     * @param array<string, string> $claims
     * @param list<string> $groups
     * @param non-empty-list<AuthenticationMethod> $methods
     */
    public function __construct(
        public UpstreamIdentityProvider $identityProvider,
        public string $subject,
        public EmailAddress $email,
        public array $claims,
        public ?string $phoneNumber,
        public array $groups,
        public DateTimeImmutable $authenticatedAt,
        public array $methods,
        public ?DateTimeImmutable $sessionNotOnOrAfter = null,
    ) {
    }
}
