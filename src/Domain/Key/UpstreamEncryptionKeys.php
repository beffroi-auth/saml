<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Key;

use function array_reverse;
use Beffroi\Core\Domain\Encoding\Base64Url;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Exception\RuntimeException;
use function ltrim;
use function sprintf;

/**
 * The keys one upstream identity provider encrypts for (spec/saml.md S-64 to S-66): among the keys of the tenant in
 * service, those whose algorithm is the provider's, the newest first, the order the metadata of that provider list
 * their certificates in (S-65) and the order they are tried in (S-66).
 *
 * One material is the key of one provider: a key of the provider whose modulus another key of the tenant in service
 * holds, the key of another provider or the SAML signing key, is refused rather than listed, since the provider would
 * then open what was encrypted for the other, or its certificate be the other's. The refusal names the two
 * algorithms, never the material. It is a fault of the store and not of a message, which is why it is not the one
 * failure of a decryption.
 */
final readonly class UpstreamEncryptionKeys
{
    /**
     * @param list<TenantKey> $keys the newest first
     */
    private function __construct(
        public array $keys,
    ) {
    }

    /**
     * @param list<TenantKey> $inService the keys of the tenant in service, in creation order
     *
     * @throws RuntimeException when a key of that provider shares its modulus with another key in service, or a key in
     *                          service carries a modulus that is not base64url
     */
    public static function of(array $inService, string $identityProvider): self
    {
        $keys = [];
        foreach ($inService as $key) {
            if ($key->algorithm instanceof SamlEncryptionAlgorithmInterface && $key->algorithm->identityProvider() === $identityProvider) {
                $keys[] = $key;
            }
        }
        foreach ($keys as $key) {
            self::assertItsOwn($key, $inService);
        }

        return new self(array_reverse($keys));
    }

    /**
     * @param list<TenantKey> $inService
     *
     * @throws RuntimeException
     */
    private static function assertItsOwn(TenantKey $key, array $inService): void
    {
        $modulus = self::modulusOf($key);
        foreach ($inService as $other) {
            if ($other === $key || self::modulusOf($other) !== $modulus) {
                continue;
            }

            throw new RuntimeException(sprintf(
                'A key of %s holds the modulus of a key of %s: one key belongs to one identity provider (spec/saml.md S-64).',
                $key->algorithm->name(),
                $other->algorithm->name(),
            ));
        }
    }

    /**
     * The modulus of an RSA key as the integer its "n" encodes (RFC 7518 §6.3.1.1), its octets without the zeros that
     * may lead them, so that two spellings of one integer are one modulus, and null for a key of another type, which
     * carries none. An "n" that is not base64url, a line or a space in it among others, which the reader of a private
     * key would skip, is a fault of the store and refused rather than compared as text.
     *
     * @throws RuntimeException
     */
    private static function modulusOf(TenantKey $key): ?string
    {
        $n = $key->publicJwk['n'] ?? null;
        if ($n === null) {
            return null;
        }
        $octets = Base64Url::decode($n) ?? throw new RuntimeException(sprintf(
            'A key of %s carries a modulus that is not base64url (RFC 7518 §6.3.1.1, spec/saml.md S-64).',
            $key->algorithm->name(),
        ));

        return ltrim($octets, "\0");
    }
}
