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
 * declaration pins, which then carries a validUntil and is held to the document accepted (S-6), each saying which of
 * the two read it. A refusal of the model, of Core or of Dsig becomes
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

        return self::metadataOf($descriptor, self::role($descriptor), false);
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

        return self::metadataOf($descriptor, self::role($descriptor), true);
    }

    /**
     * The accepted document of a service provider read back once (spec/saml.md section 6.3 step 1), with readTrusted(),
     * the channel being its own sealed store: what the signature of its requests needs, and the model's role, which
     * validates them and holds the assertion consumer services an answer goes to (S-10).
     *
     * @throws MetadataRefusedException
     */
    public function readAccepted(string $document): ReadServiceProvider
    {
        try {
            $descriptor = $this->reader->readTrusted($this->loader->load($document));
        } catch (RefusedXml $exception) {
            throw new MetadataRefusedException($exception->getMessage(), 0, $exception);
        }
        $role = self::role($descriptor);

        return new ReadServiceProvider(self::metadataOf($descriptor, $role, false), $role);
    }

    /**
     * @throws MetadataRefusedException
     */
    private static function role(EntityDescriptor $descriptor): ServiceProvider
    {
        return $descriptor->serviceProvider ?? throw new MetadataRefusedException('The metadata hold no service provider role of SAML 2.0 (spec/saml.md S-5).');
    }

    /**
     * @param bool $readSigned whether the document was verified under the certificates a declaration pins (S-6)
     *
     * @throws MetadataRefusedException
     */
    private static function metadataOf(EntityDescriptor $descriptor, ServiceProvider $role, bool $readSigned): ServiceProviderMetadata
    {
        try {
            $encryptionCertificates = array_map(
                static fn (string $base64): Certificate => new Certificate($base64),
                $role->encryptionCertificates,
            );
            $signingCertificates = array_map(
                static fn (string $base64): Certificate => new Certificate($base64),
                $role->signingCertificates,
            );
        } catch (InvalidArgumentException $exception) {
            throw new MetadataRefusedException($exception->getMessage(), 0, $exception);
        }

        return new ServiceProviderMetadata(
            $descriptor->entityId,
            $descriptor->validUntil,
            $encryptionCertificates,
            $role->authnRequestsSigned,
            $signingCertificates,
            $readSigned,
        );
    }
}
