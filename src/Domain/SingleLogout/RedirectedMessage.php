<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleLogout;

final readonly class RedirectedMessage
{
    public function __construct(
        public string $url,
    ) {
    }
}
