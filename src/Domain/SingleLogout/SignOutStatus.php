<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleLogout;

/**
 * What the answer to a LogoutRequest says (spec/saml.md S-24), a status the protocol fixes (SAML Core §3.2.2.2): the
 * sessions named ended, or none of them, the principal not being the user of one, or the request naming none.
 */
enum SignOutStatus: string
{
    case Success = 'urn:oasis:names:tc:SAML:2.0:status:Success';

    case UnknownPrincipal = 'urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal';

    case RequestUnsupported = 'urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported';

    public const string REQUESTER = 'urn:oasis:names:tc:SAML:2.0:status:Requester';

    /**
     * The top-level status code: Success itself, Requester above the second-level code of a refusal.
     */
    public function topLevel(): string
    {
        return $this === self::Success ? $this->value : self::REQUESTER;
    }

    /**
     * The second-level status code, null for Success.
     */
    public function secondLevel(): ?string
    {
        return $this === self::Success ? null : $this->value;
    }
}
