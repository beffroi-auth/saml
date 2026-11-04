<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleLogout;

use Beffroi\Core\Domain\Encoding\Base64Url;
use function random_bytes;

final readonly class LogoutChainSecret
{
    public const int BYTES = 32;

    /**
     * @param string $value in base64url
     */
    public function __construct(
        public string $value,
    ) {
    }

    public static function draw(): self
    {
        return new self(Base64Url::encode(random_bytes(self::BYTES)));
    }

    public function digest(): string
    {
        return LogoutChain::digestOf($this->value);
    }
}
