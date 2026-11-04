<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleLogout;

use Beffroi\Saml\Domain\SingleSignOn\PostedForm;

final readonly class LogoutChainEnded
{
    public function __construct(
        public ?string $continueTo,
        public PostedForm|RedirectedMessage|null $answer = null,
    ) {
    }
}
