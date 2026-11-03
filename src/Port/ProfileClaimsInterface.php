<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

/**
 * The claims the profile of a person holds in this deployment, which an attribute of an upstream identity provider
 * fills (spec/saml.md S-45): the application reads them where the pages of the account do, so that a claim one writes is
 * one the other knows.
 */
interface ProfileClaimsInterface
{
    /**
     * @return list<string>
     */
    public function names(): array;
}
