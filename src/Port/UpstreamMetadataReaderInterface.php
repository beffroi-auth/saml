<?php

declare(strict_types=1);

namespace Beffroi\Saml\Port;

use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml\Domain\Upstream\UpstreamMetadata;
use Beffroi\Saml\Exception\MetadataRefusedException;

/**
 * The metadata of an upstream identity provider read by saml2-model's MetadataReader (spec/saml.md S-42, S-43,
 * section 6.10 step 3).
 */
interface UpstreamMetadataReaderInterface
{
    /**
     * A document the channel it came through vouches for: a file of the deployment or an https URL its configuration
     * names. What it returns says it was not read signed, so that it replaces the document accepted whatever its
     * validUntil (S-6).
     *
     * @throws MetadataRefusedException what the model, Core or Dsig refuse (model.md section 6.5), a document without
     *                                  an identity provider role, one whose role holds no key for signing, and one
     *                                  with a single sign-on service that is not https on a host
     */
    public function readTrusted(string $document): UpstreamMetadata;

    /**
     * A document signed by one of the certificates the declaration pins, carrying a validUntil (S-6). What it returns
     * says it was read signed, so that it is never older than the document accepted (S-6).
     *
     * @param list<Certificate> $signers
     *
     * @throws MetadataRefusedException as readTrusted(), an unsigned document, one signed under another key, and one
     *                                  without validUntil
     */
    public function readSigned(string $document, array $signers): UpstreamMetadata;
}
