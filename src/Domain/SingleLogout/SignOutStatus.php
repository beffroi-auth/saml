<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleLogout;

/**
 * spec/saml.md S-24, S-34, SAML Core §3.2.2.2
 */
enum SignOutStatus: string
{
    case Success = 'urn:oasis:names:tc:SAML:2.0:status:Success';

    /**
     * SAML Core §3.7.3.2: a second-level code under Success, since the logout of the requester happened.
     */
    case PartialLogout = 'urn:oasis:names:tc:SAML:2.0:status:PartialLogout';

    case UnknownPrincipal = 'urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal';

    case RequestUnsupported = 'urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported';

    public const string REQUESTER = 'urn:oasis:names:tc:SAML:2.0:status:Requester';

    public function topLevel(): string
    {
        return match ($this) {
            self::Success, self::PartialLogout => self::Success->value,
            default => self::REQUESTER,
        };
    }

    public function secondLevel(): ?string
    {
        return $this === self::Success ? null : $this->value;
    }
}
