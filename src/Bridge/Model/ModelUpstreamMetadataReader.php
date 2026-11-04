<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml\Domain\Upstream\UpstreamMetadata;
use Beffroi\Saml\Exception\MetadataRefusedException;
use Beffroi\Saml\Port\UpstreamMetadataReaderInterface;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Psr\Clock\ClockInterface;

/**
 * spec/saml.md section 6.10 step 3, S-42, S-43
 */
final readonly class ModelUpstreamMetadataReader implements UpstreamMetadataReaderInterface
{
    private MetadataDocumentReader $documents;

    public function __construct(ClockInterface $clock)
    {
        $this->documents = new MetadataDocumentReader($clock);
    }

    public function readTrusted(string $document): UpstreamMetadata
    {
        return self::metadataOf($this->documents->trusted($document), false);
    }

    public function readSigned(string $document, array $signers): UpstreamMetadata
    {
        return self::metadataOf($this->documents->signed($document, $signers), true);
    }

    /**
     * S-48, section 6.11 step 4: held to S-42 and S-43 again.
     *
     * @throws MetadataRefusedException
     */
    public function readAccepted(string $document): IdentityProvider
    {
        $role = self::role($this->documents->trusted($document));
        self::signingCertificatesOf($role);

        return $role;
    }

    /**
     * @throws MetadataRefusedException
     */
    private static function metadataOf(EntityDescriptor $descriptor, bool $readSigned): UpstreamMetadata
    {
        return new UpstreamMetadata(
            $descriptor->entityId,
            $descriptor->validUntil,
            self::signingCertificatesOf(self::role($descriptor)),
            $readSigned,
        );
    }

    /**
     * S-42, S-43
     *
     * @throws MetadataRefusedException
     */
    private static function role(EntityDescriptor $descriptor): IdentityProvider
    {
        $role =
            $descriptor->identityProvider ?? throw new MetadataRefusedException('The metadata hold no identity provider role of SAML 2.0 (spec/saml.md S-42).');
        self::singleSignOnServicesOf($role);

        return $role;
    }

    /**
     * S-43
     *
     * @return list<Certificate>
     *
     * @throws MetadataRefusedException
     */
    private static function signingCertificatesOf(IdentityProvider $role): array
    {
        $signingCertificates = MetadataDocumentReader::certificates($role->signingCertificates);
        if ($signingCertificates === []) {
            throw new MetadataRefusedException('The metadata of the identity provider hold no key for signing, and nothing it sends could be verified (spec/saml.md S-43).');
        }

        return $signingCertificates;
    }

    /**
     * S-43: every single sign-on service is an https URL on a host.
     *
     * @throws MetadataRefusedException
     */
    private static function singleSignOnServicesOf(IdentityProvider $role): void
    {
        foreach ($role->singleSignOnServices as $endpoint) {
            MetadataDocumentReader::assertHttpsOnAHost($endpoint->location, 'Location', 'md:SingleSignOnService', 'the service provider', 'S-43');
        }
    }
}
