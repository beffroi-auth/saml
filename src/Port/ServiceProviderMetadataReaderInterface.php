<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml\Domain\ServiceProvider\ServiceProviderMetadata;
use Beffroi\Saml\Exception\MetadataRefusedException;

/**
 * The metadata of a service provider read by saml2-model's MetadataReader (spec/saml.md S-5, section 6.2 step 3).
 */
interface ServiceProviderMetadataReaderInterface
{
    /**
     * A document the channel it came through vouches for: a file of the deployment, an https URL its configuration
     * names, or the store of the provider itself. What it returns says it was not read signed, so that it replaces the
     * document accepted whatever its validUntil (S-6).
     *
     * @throws MetadataRefusedException what the model, Core or Dsig refuse (model.md section 6.5), and a document
     *                                  without a service provider role
     */
    public function readTrusted(string $document): ServiceProviderMetadata;

    /**
     * A document signed by one of the certificates the declaration pins, carrying a validUntil (S-6). What it returns
     * says it was read signed, so that it is never older than the document accepted (S-6).
     *
     * @param list<Certificate> $signers
     *
     * @throws MetadataRefusedException as readTrusted(), an unsigned document, one signed under another key, and one
     *                                  without validUntil
     */
    public function readSigned(string $document, array $signers): ServiceProviderMetadata;
}
