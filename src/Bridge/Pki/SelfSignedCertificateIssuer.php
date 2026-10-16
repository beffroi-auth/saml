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
use function base64_encode;
use DateInterval;
use DateTimeImmutable;
use function hash;
use function is_string;
use function openssl_pkey_export;
use function openssl_verify;
use function ord;
use OpenSSLAsymmetricKey;
use function sprintf;
use function str_split;
use SpomkyLabs\Pki\ASN1\Type\Primitive\NullType;
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
use function substr;
use Throwable;

/**
 * The self-signed certificate around a SAML key of a tenant, built with pki-framework (spec/saml.md section 6.1 step
 * 2, S-3): X.509 version 3, a serial number drawn from the "kid", the slug of the tenant for its subject and its
 * issuer, valid from the creation of the key, to the second, for ten years, the public key of the key's JWK, keyUsage
 * digitalSignature alone, signed sha256WithRSAEncryption by the key itself, its parameters NULL as RFC 4055 §5 requires
 * of a producer, whose PKCS #1 v1.5 signature is deterministic: built twice, it is the same bytes.
 *
 * It is verified under its own public key before it is returned, the result of openssl_verify() compared to 1 and
 * never to a boolean: the function answers -1 on an error, which PHP holds for true. The private half is turned into
 * a key of OpenSSL in memory for that one signature (RsaPrivateKey) and goes out of scope with it (S-1).
 */
final readonly class SelfSignedCertificateIssuer implements CertificateIssuerInterface
{
    /**
     * How long the certificate is valid from the creation of its key (section 6.1 step 2): ten years, as hosted
     * identity providers issue theirs, a date before 2050 being written as UTCTime, where Entra refuses a certificate
     * valid until 9999-12-31 in GeneralizedTime (section 7).
     */
    public const string VALIDITY = 'P10Y';

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
        $private = RsaPrivateKey::of($key);

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
     * The certificate, each of its fields a function of the key and of its tenant (section 6.1 step 2).
     */
    private static function sign(TenantKey $key, OpenSSLAsymmetricKey $private): X509Certificate
    {
        if (! openssl_pkey_export($private, $pem) || ! is_string($pem)) {
            throw new RuntimeException(sprintf('OpenSSL cannot export the key "%s".', $key->kid));
        }
        $privateKeyInfo = PrivateKeyInfo::fromDER(PEM::fromString($pem)->data());
        $name = Name::fromString('cn=' . $key->tenant->slug);
        $notBefore = new DateTimeImmutable('@' . $key->createdAt->getTimestamp());
        // pki-framework writes a date before 2050 as UTCTime and a later one as GeneralizedTime (RFC 5280 §4.1.2.5)
        $validity = Validity::create(Time::create($notBefore), Time::create($notBefore->add(new DateInterval(self::VALIDITY))));

        return TBSCertificate::create($name, $privateKeyInfo->publicKeyInfo(), $name, $validity)
            ->withVersion(TBSCertificate::VERSION_3)
            ->withSerialNumber(self::serialNumber($key))
            ->withExtensions(Extensions::create(KeyUsageExtension::create(true, KeyUsageExtension::DIGITAL_SIGNATURE)))
            ->sign(SHA256WithRSAEncryptionAlgorithmIdentifier::create(NullType::create()), $privateKeyInfo);
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
