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
 * The metadata of an upstream identity provider read by saml2-model's MetadataReader, through MetadataDocumentReader
 * (spec/saml.md section 6.10 step 3): readTrusted() for a document its channel vouches for, readSigned() for one
 * signed under the certificates a declaration pins, which then carries a validUntil and is held to the document
 * accepted (S-6). Each refuses a document without an identity provider role (S-42), one whose role holds no key for
 * signing, and one with a single sign-on service the service provider would send a browser to that is not https on a
 * host (S-43). Its single logout services, its NameID formats and its WantAuthnRequestsSigned are not read (S-43).
 *
 * The accepted document is read back the same way, with readTrusted(), the channel being the provider's own sealed
 * store, when the service provider sends the provider a request (S-48, section 6.11 step 4): the model's role, which
 * holds the single sign-on services.
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
     * The accepted document of an upstream identity provider read back (spec/saml.md S-48, section 6.11 step 4), held
     * to S-42 and S-43 again: the model's role.
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
     * @param bool $readSigned whether the document was verified under the certificates a declaration pins (S-6)
     *
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
     * S-42, S-43: the identity provider role of SAML 2.0 the document holds, its single sign-on services each https on
     * a host.
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
     * S-43: the certificates of the role a key for signing is in, one at least: an assertion of the provider is
     * verified under them and under nothing it carries.
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
     * S-43: the Location of every md:SingleSignOnService the model kept, on HTTP-Redirect or HTTP-POST, is an https URL
     * on a host (EndpointLocation): the service provider sends the browser there with its request.
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
