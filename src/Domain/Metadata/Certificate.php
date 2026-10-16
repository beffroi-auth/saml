<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Metadata;

use Beffroi\Core\Exception\InvalidArgumentException;
use function base64_decode;
use function base64_encode;
use function chunk_split;
use function is_string;

/**
 * An X.509 certificate as an X509Certificate of metadata carries it (spec/saml.md section 5.1): the base64 of its DER,
 * in the alphabet of RFC 4648 §4, with its padding and nothing else, so that what is published is what was built.
 * What it holds is public; the key it is around is never here (S-1).
 */
final readonly class Certificate
{
    /**
     * @throws InvalidArgumentException when the value is not the canonical base64 of some bytes
     */
    public function __construct(
        public string $base64,
    ) {
        $der = base64_decode($base64, true);
        if (! is_string($der) || $der === '' || base64_encode($der) !== $base64) {
            throw new InvalidArgumentException('A certificate is the base64 of its DER, in the alphabet of RFC 4648 section 4 (spec/saml.md section 5.1).');
        }
    }

    /**
     * The certificate in the textual encoding of RFC 7468 §5, lines of 64 characters, for what takes a PEM: the
     * KeyInfo of every signature of the provider (S-37).
     */
    public function pem(): string
    {
        return "-----BEGIN CERTIFICATE-----\n" . chunk_split($this->base64, 64, "\n") . "-----END CERTIFICATE-----\n";
    }
}
