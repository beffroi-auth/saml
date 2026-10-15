<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleSignOn;

/**
 * The failures single sign-on answers a request with (spec/saml.md section 6.4 step 4): a closed set the protocol
 * fixes, the second-level status codes of Core §3.2.2.2 this identity provider writes, which a failure carries and
 * nothing acts on. Each sits under the top-level code Core gives its cause.
 */
enum SignOnStatus: string
{
    /**
     * Core §3.4.1: IsPassive, and no session that answers without a page.
     */
    case NoPassive = 'urn:oasis:names:tc:SAML:2.0:status:NoPassive';

    /**
     * Core §3.3.2.2.1: a context asked for that the identity provider does not state.
     */
    case NoAuthnContext = 'urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext';

    /**
     * Core §3.4.1.1: a NameIDPolicy of a format the identity provider does not write.
     */
    case InvalidNameIdPolicy = 'urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy';

    public const string REQUESTER = 'urn:oasis:names:tc:SAML:2.0:status:Requester';

    public const string RESPONDER = 'urn:oasis:names:tc:SAML:2.0:status:Responder';

    /**
     * The top-level code: the requester asked for what is never written, the responder could not do what was asked.
     */
    public function topLevel(): string
    {
        return $this === self::InvalidNameIdPolicy ? self::REQUESTER : self::RESPONDER;
    }
}
