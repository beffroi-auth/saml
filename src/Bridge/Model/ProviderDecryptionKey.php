<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use Beffroi\Xml\Enc\DecryptionKeyInterface;
use Beffroi\Xml\Enc\Exception\AlgorithmUnavailable;
use Beffroi\Xml\Enc\OaepHash;

/**
 * The key the model is given with one upstream identity provider (spec/saml.md S-66): the keys of that provider in
 * service, opened, in the order its metadata list their certificates, the newest first, and none of another provider.
 * Enc's Decryptor hands it the session key an EncryptedKey wraps, once; it hands that to each key in turn and answers
 * the first session key that unwraps, or nothing, never why (enc.md E-6).
 *
 * The KeyInfo of the EncryptedKey, which may name the certificate the session key was wrapped for, is not read: every
 * key tried is the provider's own, and RSA-OAEP refuses a key that is not the one a session key was wrapped for by its
 * own check (RFC 8017 §7.1.2).
 */
final readonly class ProviderDecryptionKey implements DecryptionKeyInterface
{
    /**
     * @param list<DecryptionKeyInterface> $keys the keys of one provider, opened, in the order they are tried
     */
    public function __construct(
        private array $keys,
    ) {
    }

    /**
     * @throws AlgorithmUnavailable when this build cannot unwrap under $hash
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
