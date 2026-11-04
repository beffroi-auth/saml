<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Metadata;

use Beffroi\Core\Exception\InvalidArgumentException;
use function preg_match;
use function str_starts_with;

/**
 * An https URL or the absolute path of a file, never plain http (decision 0006): the channel is what readTrusted()
 * trusts when the declaration pins no signer.
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
