<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use function array_map;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml\Domain\Metadata\EndpointLocation;
use Beffroi\Saml\Exception\MetadataRefusedException;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Loader;
use Beffroi\Xml\Dsig\VerificationKey;
use Beffroi\Xml\Dsig\VerificationKeys;
use DateTimeImmutable;
use Psr\Clock\ClockInterface;
use function sprintf;

/**
 * spec/saml.md section 6.2 step 3, section 6.10 step 3, S-6, M-7, M-16
 */
final readonly class MetadataDocumentReader
{
    private Loader $loader;

    private MetadataReader $reader;

    public function __construct(ClockInterface $clock)
    {
        $this->loader = SamlLoader::create();
        $this->reader = new MetadataReader($this->loader, $clock);
    }

    /**
     * @throws MetadataRefusedException
     */
    public function trusted(string $document): EntityDescriptor
    {
        try {
            return $this->reader->readTrusted($this->loader->load($document));
        } catch (RefusedXml $exception) {
            throw new MetadataRefusedException($exception->getMessage(), 0, $exception);
        }
    }

    /**
     * @param list<Certificate> $signers
     *
     * @throws MetadataRefusedException
     */
    public function signed(string $document, array $signers): EntityDescriptor
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

        return $descriptor;
    }

    /**
     * @param list<string> $base64
     *
     * @return list<Certificate>
     *
     * @throws MetadataRefusedException
     */
    public static function certificates(array $base64): array
    {
        try {
            return array_map(static fn (string $certificate): Certificate => new Certificate($certificate), $base64);
        } catch (InvalidArgumentException $exception) {
            throw new MetadataRefusedException($exception->getMessage(), 0, $exception);
        }
    }

    /**
     * S-11, S-43, M-16
     *
     * @param string $party "the identity provider" or "the service provider"
     *
     * @throws MetadataRefusedException
     */
    public static function assertHttpsOnAHost(string $location, string $attribute, string $element, string $party, string $rule): void
    {
        if (! EndpointLocation::isHttpsOnAHost($location)) {
            throw new MetadataRefusedException(sprintf(
                'The %s of an %s is not an https URL on a host name or an IP address, and %s sends a browser there (spec/saml.md %s).',
                $attribute,
                $element,
                $party,
                $rule,
            ));
        }
    }
}
