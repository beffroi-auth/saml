<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Upstream;

use Beffroi\Saml\Domain\SingleLogout\RedirectedMessage;
use Beffroi\Saml\Domain\SingleSignOn\PostedForm;

final readonly class SentAuthnRequest
{
    public function __construct(
        public UpstreamAuthnRequest $request,
        public string $id,
        public PostedForm|RedirectedMessage $message,
    ) {
    }
}
