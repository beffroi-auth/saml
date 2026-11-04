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
 * spec/saml.md S-64 to S-66. A key whose modulus another key in service holds is refused, or one provider could open
 * what was encrypted for another; the refusal names the two algorithms, never the material.
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
     * @param list<TenantKey> $inService in creation order
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
     * RFC 7518 §6.3.1.1. Leading zero octets are dropped and an "n" that is not strict base64url is refused, so that
     * two spellings of one modulus are never two moduli.
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
