<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleLogout;

use Beffroi\Saml\Domain\SingleSignOn\PostedForm;

final readonly class SentSignOutNotice
{
    public function __construct(
        public string $id,
        public PostedForm|RedirectedMessage $message,
    ) {
    }
}
