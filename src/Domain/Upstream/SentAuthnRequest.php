<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Upstream;

use Beffroi\Saml\Domain\SingleLogout\RedirectedMessage;
use Beffroi\Saml\Domain\SingleSignOn\PostedForm;

/**
 * An AuthnRequest written and signed for an upstream identity provider (spec/saml.md S-48, section 6.11 step 5): what
 * it was written from, its RelayState among it (S-50); its ID, which the InResponseTo of a response names; and what
 * carries it, the URL of HTTP-Redirect or the form of HTTP-POST.
 */
final readonly class SentAuthnRequest
{
    public function __construct(
        public UpstreamAuthnRequest $request,
        public string $id,
        public PostedForm|RedirectedMessage $message,
    ) {
    }
}
