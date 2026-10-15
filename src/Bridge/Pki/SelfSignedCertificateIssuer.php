<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Pki;

use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Key\UnsealedKey;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Saml\Domain\Key\SamlSigningAlgorithmInterface;
use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml\Port\CertificateIssuerInterface;
use function base64_decode;
use function base64_encode;
use DateTimeImmutable;
use function hash;
use function hash_equals;
use function is_string;
use function openssl_pkey_export;
use function openssl_pkey_new;
use function openssl_verify;
use function ord;
use OpenSSLAsymmetricKey;
use SensitiveParameter;
use function sprintf;
use function str_split;
use SpomkyLabs\Pki\CryptoEncoding\PEM;
use SpomkyLabs\Pki\CryptoTypes\AlgorithmIdentifier\Signature\SHA256WithRSAEncryptionAlgorithmIdentifier;
use SpomkyLabs\Pki\CryptoTypes\Asymmetric\PrivateKeyInfo;
use SpomkyLabs\Pki\X501\ASN1\Name;
use SpomkyLabs\Pki\X509\Certificate\Certificate as X509Certificate;
use SpomkyLabs\Pki\X509\Certificate\Extension\KeyUsageExtension;
use SpomkyLabs\Pki\X509\Certificate\Extensions;
use SpomkyLabs\Pki\X509\Certificate\TBSCertificate;
use SpomkyLabs\Pki\X509\Certificate\Time;
use SpomkyLabs\Pki\X509\Certificate\Validity;
use function strtr;
use function substr;
use Throwable;

/**
 * The self-signed certificate around a SAML key of a tenant, built with pki-framework (spec/saml.md section 6.1 step
 * 2, S-3): X.509 version 3, a serial number drawn from the "kid", the slug of the tenant for its subject and its
 * issuer, valid from the creation of the key with no well-defined expiration date (RFC 5280 §4.1.2.5), the public key
 * of the key's JWK, keyUsage digitalSignature alone, signed sha256WithRSAEncryption by the key itself, whose PKCS #1
 * v1.5 signature is deterministic: built twice, it is the same bytes.
 *
 * It is verified under its own public key before it is returned, the result of openssl_verify() compared to 1 and
 * never to a boolean: the function answers -1 on an error, which PHP holds for true. The private half is turned into
 * a key of OpenSSL in memory for that one signature and goes out of scope with it (S-1).
 */
final readonly class SelfSignedCertificateIssuer implements CertificateIssuerInterface
{
    /**
     * RFC 5280 §4.1.2.5: the notAfter of a certificate with no well-defined expiration date. The life of the key is
     * its status, and a certificate in metadata is the notation of a key (Metadata Interoperability Profile §2.6.1).
     */
    public const string NOT_AFTER = '9999-12-31T23:59:59Z';

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

    public function selfSigned(UnsealedKey $key): Certificate
    {
        $tenantKey = $key->key;
        if (! $tenantKey->algorithm instanceof SamlSigningAlgorithmInterface) {
            throw new InvalidArgumentException(sprintf(
                'The key "%s" is of %s, not a SAML signing key: its certificate is not one the metadata publishes (spec/saml.md section 6.1 step 2).',
                $tenantKey->kid,
                $tenantKey->algorithm->name(),
            ));
        }
        $private = self::privateKey($tenantKey, $key->privateJwk);

        try {
            $certificate = self::sign($tenantKey, $private);
            $signedBytes = $certificate->tbsCertificate()->toASN1()->toDER();
            $signature = $certificate->signatureValue()->bitString()->string();
            $publicPem = $certificate->tbsCertificate()->subjectPublicKeyInfo()->toPEM()->string();
            $der = $certificate->toDER();
        } catch (Throwable $failure) {
            throw new RuntimeException(sprintf('The certificate of the key "%s" cannot be signed.', $tenantKey->kid), 0, $failure);
        }

        // compared to 1: openssl_verify() answers -1 on an error, which is true as a boolean (S-3)
        if (openssl_verify($signedBytes, $signature, $publicPem, OPENSSL_ALGO_SHA256) !== 1) {
            throw new RuntimeException(sprintf(
                'The certificate of the key "%s" does not verify under its own public key: its private half is not the one of its public JWK (spec/saml.md section 6.1 step 2).',
                $tenantKey->kid,
            ));
        }

        return new Certificate(base64_encode($der));
    }

    /**
     * The private half as a key of OpenSSL, its modulus and its exponent first compared with those of the public JWK
     * the metadata publishes, so that nothing is signed with a key that is not that one.
     *
     * @param array<string, string> $privateJwk
     *
     * @throws InvalidArgumentException
     */
    private static function privateKey(TenantKey $key, #[SensitiveParameter] array $privateJwk): OpenSSLAsymmetricKey
    {
        $components = [];
        foreach (self::PRIVATE_MEMBERS as $member => $component) {
            $components[$component] = self::bytes($key, $privateJwk, $member);
        }
        foreach (['n', 'e'] as $member) {
            if (! hash_equals(self::bytes($key, $key->publicJwk, $member), $components[$member])) {
                throw new InvalidArgumentException(sprintf(
                    'The private half of the key "%s" is not the one of its public JWK: its "%s" differs (spec/saml.md section 6.1 step 2).',
                    $key->kid,
                    $member,
                ));
            }
        }
        $private = openssl_pkey_new([
            'rsa' => $components,
        ]);
        if (! $private instanceof OpenSSLAsymmetricKey) {
            throw new InvalidArgumentException(sprintf('The private half of the key "%s" is not an RSA key OpenSSL takes.', $key->kid));
        }

        return $private;
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

    /**
     * The certificate, each of its fields a function of the key and of its tenant (section 6.1 step 2).
     */
    private static function sign(TenantKey $key, OpenSSLAsymmetricKey $private): X509Certificate
    {
        if (! openssl_pkey_export($private, $pem) || ! is_string($pem)) {
            throw new RuntimeException(sprintf('OpenSSL cannot export the key "%s".', $key->kid));
        }
        $privateKeyInfo = PrivateKeyInfo::fromDER(PEM::fromString($pem)->data());
        $name = Name::fromString('cn=' . $key->tenant->slug);
        $validity = Validity::create(
            Time::create(new DateTimeImmutable('@' . $key->createdAt->getTimestamp())),
            Time::create(new DateTimeImmutable(self::NOT_AFTER)),
        );

        return TBSCertificate::create($name, $privateKeyInfo->publicKeyInfo(), $name, $validity)
            ->withVersion(TBSCertificate::VERSION_3)
            ->withSerialNumber(self::serialNumber($key))
            ->withExtensions(Extensions::create(KeyUsageExtension::create(true, KeyUsageExtension::DIGITAL_SIGNATURE)))
            ->sign(SHA256WithRSAEncryptionAlgorithmIdentifier::create(), $privateKeyInfo);
    }

    /**
     * One more than the first seven bytes of the SHA-256 of the "kid", read as an unsigned integer: positive and at
     * most 20 octets (RFC 5280 §4.1.2.2), and the same for the same key.
     */
    private static function serialNumber(TenantKey $key): int
    {
        $serial = 0;
        foreach (str_split(substr(hash('sha256', $key->kid, true), 0, 7)) as $byte) {
            $serial = ($serial << 8) | ord($byte);
        }

        return $serial + 1;
    }
}
