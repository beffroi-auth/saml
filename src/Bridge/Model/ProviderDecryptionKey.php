<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use Beffroi\Xml\Enc\DecryptionKeyInterface;
use Beffroi\Xml\Enc\Exception\AlgorithmUnavailable;
use Beffroi\Xml\Enc\OaepHash;

/**
 * spec/saml.md S-66, enc.md E-6: the keys of one provider are tried in turn and the first session key that unwraps is
 * answered, or nothing, never why. The KeyInfo is not read: RSA-OAEP refuses a key a session key was not wrapped for
 * (RFC 8017 §7.1.2).
 */
final readonly class ProviderDecryptionKey implements DecryptionKeyInterface
{
    /**
     * @param list<DecryptionKeyInterface> $keys in the order they are tried
     */
    public function __construct(
        private array $keys,
    ) {
    }

    /**
     * @throws AlgorithmUnavailable
     */
    public function unwrap(string $wrapped, OaepHash $hash): ?string
    {
        foreach ($this->keys as $key) {
            $sessionKey = $key->unwrap($wrapped, $hash);
            if ($sessionKey !== null) {
                return $sessionKey;
            }
        }

        return null;
    }
}
