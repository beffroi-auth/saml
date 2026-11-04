<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Upstream;

use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Session\AuthenticationMethod;
use DateTimeImmutable;

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
