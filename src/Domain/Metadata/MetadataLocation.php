<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Metadata;

use Beffroi\Core\Exception\InvalidArgumentException;
use function preg_match;
use function str_starts_with;

/**
 * Where the metadata of a peer are read from, a service provider (spec/saml.md S-5) or an upstream identity provider
 * (S-42): an `https` URL, or the absolute path of a file of the deployment, and nothing else, a plain `http` URL
 * included (decision 0006). The channel is what `readTrusted()` trusts when the declaration pins no signer.
 */
final readonly class MetadataLocation
{
    /**
     * @throws InvalidArgumentException when the value is neither (section 6.2 step 1)
     */
    public function __construct(
        public string $value,
    ) {
        if (! Lexical::isName($value) || ! (preg_match('#^https://[^/?\#@]+(?:[/?\#]|\z)#', $value) === 1 || str_starts_with($value, '/'))) {
            throw new InvalidArgumentException('The metadata of a service provider or of an identity provider are read from an https URL or from the absolute path of a file (spec/saml.md S-5, S-42).');
        }
    }
}
