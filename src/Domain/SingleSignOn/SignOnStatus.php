<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleSignOn;

/**
 * spec/saml.md section 6.4 step 4, Core §3.2.2.2
 */
enum SignOnStatus: string
{
    /**
     * Core §3.4.1
     */
    case NoPassive = 'urn:oasis:names:tc:SAML:2.0:status:NoPassive';

    /**
     * Core §3.3.2.2.1
     */
    case NoAuthnContext = 'urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext';

    /**
     * Core §3.4.1.1
     */
    case InvalidNameIdPolicy = 'urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy';

    public const string REQUESTER = 'urn:oasis:names:tc:SAML:2.0:status:Requester';

    public const string RESPONDER = 'urn:oasis:names:tc:SAML:2.0:status:Responder';

    public function topLevel(): string
    {
        return $this === self::InvalidNameIdPolicy ? self::REQUESTER : self::RESPONDER;
    }
}
