<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleLogout;

/**
 * What the answer to a LogoutRequest says (spec/saml.md S-24, S-34), a status the protocol fixes (SAML Core §3.2.2.2):
 * the sessions named ended, and every other service provider of them told; ended, and one of the others not told; or
 * none of them ended, the principal not being the user of one, or the request naming none.
 */
enum SignOutStatus: string
{
    case Success = 'urn:oasis:names:tc:SAML:2.0:status:Success';

    /**
     * The sessions ended, a service provider told of them having answered otherwise than Success, or not at all
     * (SAML Core §3.7.3.2): a second-level code under Success, since the logout of the requester happened.
     */
    case PartialLogout = 'urn:oasis:names:tc:SAML:2.0:status:PartialLogout';

    case UnknownPrincipal = 'urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal';

    case RequestUnsupported = 'urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported';

    public const string REQUESTER = 'urn:oasis:names:tc:SAML:2.0:status:Requester';

    /**
     * The top-level status code: Success for a logout done, partially or not, Requester above the second-level code
     * of a refusal.
     */
    public function topLevel(): string
    {
        return match ($this) {
            self::Success, self::PartialLogout => self::Success->value,
            default => self::REQUESTER,
        };
    }

    /**
     * The second-level status code, null for Success.
     */
    public function secondLevel(): ?string
    {
        return $this === self::Success ? null : $this->value;
    }
}
