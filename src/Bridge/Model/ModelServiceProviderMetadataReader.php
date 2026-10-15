<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use function array_map;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml\Domain\ServiceProvider\ServiceProviderMetadata;
use Beffroi\Saml\Exception\MetadataRefusedException;
use Beffroi\Saml\Port\ServiceProviderMetadataReaderInterface;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Dsig\VerificationKey;
use Beffroi\Xml\Dsig\VerificationKeys;
use DateTimeImmutable;
use Psr\Clock\ClockInterface;

/**
 * The metadata of a service provider read by saml2-model's MetadataReader, loaded by SamlLoader (spec/saml.md
 * section 6.2 steps 3 and 4): model.md section 6.5 in order, the validity of M-7 against the clock of the deployment
 * among it. readTrusted() for a document its channel vouches for, readSigned() for one signed under the certificates a
 * declaration pins, which then carries a validUntil (S-6). A refusal of the model, of Core or of Dsig becomes
 * MetadataRefusedException with its message, which names a rule and never a value of the document (M-16).
 */
final readonly class ModelServiceProviderMetadataReader implements ServiceProviderMetadataReaderInterface
{
    private Loader $loader;

    private MetadataReader $reader;

    public function __construct(ClockInterface $clock)
    {
        $this->loader = SamlLoader::create();
        $this->reader = new MetadataReader($this->loader, $clock);
    }

    public function readTrusted(string $document): ServiceProviderMetadata
    {
        try {
            $descriptor = $this->reader->readTrusted($this->loader->load($document));
        } catch (RefusedXml $exception) {
            throw new MetadataRefusedException($exception->getMessage(), 0, $exception);
        }

        return self::metadataOf($descriptor);
    }

    public function readSigned(string $document, array $signers): ServiceProviderMetadata
    {
        if ($signers === []) {
            throw new MetadataRefusedException('Signed metadata are verified under one certificate at least (spec/saml.md S-5).');
        }
        try {
            $descriptor = $this->reader->readSigned(
                $this->loader->load($document),
                new VerificationKeys(array_map(
                    static fn (Certificate $signer): VerificationKey => VerificationKey::fromCertificateBase64($signer->base64),
                    $signers,
                )),
            );
        } catch (RefusedXml $exception) {
            throw new MetadataRefusedException($exception->getMessage(), 0, $exception);
        }
        if (! $descriptor->validUntil instanceof DateTimeImmutable) {
            throw new MetadataRefusedException('Signed metadata carry a validUntil, without which an older document signed by the same key verifies as well (spec/saml.md S-6).');
        }

        return self::metadataOf($descriptor);
    }

    /**
     * @throws MetadataRefusedException
     */
    private static function metadataOf(EntityDescriptor $descriptor): ServiceProviderMetadata
    {
        if (! $descriptor->serviceProvider instanceof ServiceProvider) {
            throw new MetadataRefusedException('The metadata hold no service provider role of SAML 2.0 (spec/saml.md S-5).');
        }
        try {
            $encryptionCertificates = array_map(
                static fn (string $base64): Certificate => new Certificate($base64),
                $descriptor->serviceProvider->encryptionCertificates,
            );
            $signingCertificates = array_map(
                static fn (string $base64): Certificate => new Certificate($base64),
                $descriptor->serviceProvider->signingCertificates,
            );
        } catch (InvalidArgumentException $exception) {
            throw new MetadataRefusedException($exception->getMessage(), 0, $exception);
        }

        return new ServiceProviderMetadata(
            $descriptor->entityId,
            $descriptor->validUntil,
            $encryptionCertificates,
            $descriptor->serviceProvider->authnRequestsSigned,
            $signingCertificates,
        );
    }
}
