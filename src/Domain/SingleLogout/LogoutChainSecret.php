<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleLogout;

use Beffroi\Core\Domain\Encoding\Base64Url;
use function random_bytes;

/**
 * The secret that binds a chain of logout to the browser that began it (spec/saml.md S-32): drawn when the chain
 * begins, kept by the chain as its SHA-256 only, held by that browser alone, which presents it at every step. How the
 * browser holds it is the application's; this package sees the secret and its digest, never where it travels.
 */
final readonly class LogoutChainSecret
{
    /**
     * The octets of a secret: 256 bits, in base64url without padding, 43 characters.
     */
    public const int BYTES = 32;

    /**
     * @param string $value the secret as the browser holds it, in base64url
     */
    public function __construct(
        public string $value,
    ) {
    }

    /**
     * A secret drawn from random_bytes() for a chain that begins.
     */
    public static function draw(): self
    {
        return new self(Base64Url::encode(random_bytes(self::BYTES)));
    }

    /**
     * What a chain keeps of the secret: its SHA-256, in hexadecimal, so that a dump of the table plays no chain.
     */
    public function digest(): string
    {
        return LogoutChain::digestOf($this->value);
    }
}
