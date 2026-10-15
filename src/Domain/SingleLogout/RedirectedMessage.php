<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleLogout;

/**
 * A message sent over HTTP-Redirect (spec/saml.md section 6.5 step 4, SAML Bindings §3.4): the URL the browser is sent
 * to, the message, its RelayState and the signature over the query string in it, which the bundle answers with a 302.
 */
final readonly class RedirectedMessage
{
    public function __construct(
        public string $url,
    ) {
    }
}
