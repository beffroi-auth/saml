<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Pki;

use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Key\UnsealedKey;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\RuntimeException;
use function base64_decode;
use function hash_equals;
use function is_string;
use function openssl_pkey_export;
use function openssl_pkey_new;
use OpenSSLAsymmetricKey;
use SensitiveParameter;
use function sprintf;
use function strtr;

/**
 * The private half of a SAML key of a tenant, opened by the KMS, as a key of OpenSSL in memory (spec/saml.md S-1): its
 * modulus and its exponent first compared with those of the public JWK the metadata publishes, so that nothing is
 * signed with a key that is not that one. What signs the certificate of the key and what signs an assertion both take
 * it from here; it goes out of scope with the signature it was made for.
 */
final readonly class RsaPrivateKey
{
    /**
     * The members of a private RSA JWK (RFC 7518 §6.3.2), by the name OpenSSL gives each.
     */
    private const array PRIVATE_MEMBERS = [
        'n' => 'n',
        'e' => 'e',
        'd' => 'd',
        'p' => 'p',
        'q' => 'q',
        'dp' => 'dmp1',
        'dq' => 'dmq1',
        'qi' => 'iqmp',
    ];

    /**
     * @throws InvalidArgumentException when the private half is not the one of the public JWK, or not RSA
     */
    public static function of(UnsealedKey $key): OpenSSLAsymmetricKey
    {
        $tenantKey = $key->key;
        $components = [];
        foreach (self::PRIVATE_MEMBERS as $member => $component) {
            $components[$component] = self::bytes($tenantKey, $key->privateJwk, $member);
        }
        foreach (['n', 'e'] as $member) {
            if (! hash_equals(self::bytes($tenantKey, $tenantKey->publicJwk, $member), $components[$member])) {
                throw new InvalidArgumentException(sprintf(
                    'The private half of the key "%s" is not the one of its public JWK: its "%s" differs (spec/saml.md section 6.1 step 2).',
                    $tenantKey->kid,
                    $member,
                ));
            }
        }
        $private = openssl_pkey_new([
            'rsa' => $components,
        ]);
        if (! $private instanceof OpenSSLAsymmetricKey) {
            throw new InvalidArgumentException(sprintf('The private half of the key "%s" is not an RSA key OpenSSL takes.', $tenantKey->kid));
        }

        return $private;
    }

    /**
     * The same key as a PEM in memory, for what takes a PEM.
     *
     * @throws InvalidArgumentException
     * @throws RuntimeException when OpenSSL cannot export it
     */
    public static function pem(UnsealedKey $key): string
    {
        if (! openssl_pkey_export(self::of($key), $pem) || ! is_string($pem)) {
            throw new RuntimeException(sprintf('OpenSSL cannot export the key "%s".', $key->key->kid));
        }

        return $pem;
    }

    /**
     * One member of a JWK, a base64url string without padding (RFC 7518 §6.3), as bytes.
     *
     * @param array<string, string> $jwk
     *
     * @throws InvalidArgumentException
     */
    private static function bytes(TenantKey $key, #[SensitiveParameter] array $jwk, string $member): string
    {
        $value = $jwk[$member] ?? '';
        $bytes = base64_decode(strtr($value, '-_', '+/'), true);
        if (! is_string($bytes) || $bytes === '') {
            throw new InvalidArgumentException(sprintf(
                'The member "%s" of the key "%s" is not a base64url integer of RFC 7518 section 6.3.',
                $member,
                $key->kid,
            ));
        }

        return $bytes;
    }
}
