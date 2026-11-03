<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Core\Domain\Identity\User;

/**
 * The claims the provider serves, which an attribute mapping names (spec/saml.md S-16): the application reads them where
 * OpenID Connect does, so that a claim is one thing whatever protocol carries it.
 */
interface ServedClaimsInterface
{
    /**
     * @return list<string>
     */
    public function names(): array;

    /**
     * The values of those claims for the user, as JSON values; a claim the user does not hold is absent.
     *
     * @param list<string> $names
     *
     * @return array<string, mixed>
     */
    public function of(User $user, array $names): array;
}
