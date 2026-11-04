<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Core\Domain\Identity\User;

interface ServedClaimsInterface
{
    /**
     * @return list<string>
     */
    public function names(): array;

    /**
     * A claim the user does not hold is absent.
     *
     * @param list<string> $names
     *
     * @return array<string, mixed> JSON values by claim name
     */
    public function of(User $user, array $names): array;
}
