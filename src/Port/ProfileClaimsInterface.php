<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

interface ProfileClaimsInterface
{
    /**
     * @return list<string>
     */
    public function names(): array;
}
