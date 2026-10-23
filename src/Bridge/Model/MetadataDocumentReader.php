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
 * A metadata document of a peer of either role read by saml2-model's MetadataReader, loaded by SamlLoader
 * (spec/saml.md section 6.2 step 3, section 6.10 step 3): model.md section 6.5 in order, the validity of M-7 against
 * the clock of the deployment among it. trusted() for a document its channel vouches for, signed() for one signed
 * under the certificates a declaration pins, which then carries a validUntil, so that it is held to the document
 * accepted (S-6). A refusal of the model, of Core or of Dsig becomes MetadataRefusedException with its message, which
 * names a rule and never a value of the document (M-16).
 *
 * What a role reads of the entity, the role itself and what it requires of it, is the reader of that role's.
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
     * The certificates of a role, each the base64 of an X509Certificate the model checked by building its key.
     *
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
     * S-11, S-43: an endpoint a browser is sent to is an https URL on a host (EndpointLocation), at every reading; the
     * refusal names the endpoint and never its value (M-16).
     *
     * @param string $party who sends the browser there, "the identity provider" or "the service provider"
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
