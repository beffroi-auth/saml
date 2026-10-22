<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Key;

use function array_reverse;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Exception\RuntimeException;
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
        public ?SamlEncryptionAlgorithmInterface $algorithm,
        public array $keys,
    ) {
    }

    /**
     * @param list<TenantKey> $inService the keys of the tenant in service, in creation order
     *
     * @throws RuntimeException when a key of that provider shares its modulus with another key in service
     */
    public static function of(array $inService, string $identityProvider): self
    {
        $algorithm = null;
        $keys = [];
        foreach ($inService as $key) {
            if ($key->algorithm instanceof SamlEncryptionAlgorithmInterface && $key->algorithm->identityProvider() === $identityProvider) {
                $algorithm = $key->algorithm;
                $keys[] = $key;
            }
        }
        foreach ($keys as $key) {
            self::assertItsOwn($key, $inService);
        }

        return new self($algorithm, array_reverse($keys));
    }

    /**
     * @param list<TenantKey> $inService
     *
     * @throws RuntimeException
     */
    private static function assertItsOwn(TenantKey $key, array $inService): void
    {
        foreach ($inService as $other) {
            if ($other === $key || self::modulusOf($other) !== self::modulusOf($key)) {
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
     * The "n" of an RSA key (RFC 7518 §6.3.1.1), which no key of another type carries.
     */
    private static function modulusOf(TenantKey $key): ?string
    {
        return $key->publicJwk['n'] ?? null;
    }
}
