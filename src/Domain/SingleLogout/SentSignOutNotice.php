<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleLogout;

use Beffroi\Saml\Domain\SingleSignOn\PostedForm;

/**
 * A LogoutRequest written and signed (spec/saml.md S-31): its ID, which the chain waits for the answer of (S-32), and
 * what carries it, the URL of HTTP-Redirect or the form of HTTP-POST.
 */
final readonly class SentSignOutNotice
{
    public function __construct(
        public string $id,
        public PostedForm|RedirectedMessage $message,
    ) {
    }
}
