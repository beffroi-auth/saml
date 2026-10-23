<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\ServiceProvider;

use function array_key_exists;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml\Domain\Metadata\Lexical;
use Beffroi\Saml\Domain\Metadata\MetadataLocation;
use Beffroi\Saml\Domain\Metadata\PeerInterface;
use function count;

/**
 * A service provider of a tenant as the deployment declares it (spec/saml.md S-5, section 5.2): its entity ID, where
 * its metadata are read from and who signs them, the claims it is sent as attributes, whether it asks for its
 * assertions encrypted (S-7), and whether it signs its authentication requests, without which none of its requests
 * is accepted unsigned (S-9). Never registered by a request nor through a page: a declaration goes away when its block does.
 */
final readonly class ServiceProvider implements PeerInterface
{
    /**
     * The `maxVerificationKeys` of Dsig, which `readSigned()` hands the signers to (section 7).
     */
    public const int MAX_METADATA_SIGNERS = 16;

    /**
     * The attributes per statement of `model.md` section 7, which the assertion of issue #731 carries (section 7).
     */
    public const int MAX_ATTRIBUTES = 256;

    /**
     * @param list<Certificate> $metadataSigners the certificates the metadata are verified under, none when the channel is trusted
     * @param list<AttributeMapping> $attributes
     *
     * @throws InvalidArgumentException when the declaration does not hold together (section 6.2 step 1)
     */
    public function __construct(
        public string $entityId,
        public MetadataLocation $metadata,
        public array $metadataSigners = [],
        public array $attributes = [],
        public bool $encryptAssertions = false,
        public bool $signsAuthnRequests = true,
    ) {
        if (! Lexical::isName($entityId)) {
            throw new InvalidArgumentException('The entity ID of a service provider is not empty, holds no whitespace and is at most 1024 characters (spec/saml.md section 6.2 step 1).');
        }
        if (count($metadataSigners) > self::MAX_METADATA_SIGNERS) {
            throw new InvalidArgumentException('A service provider pins at most 16 signers of its metadata (spec/saml.md section 7).');
        }
        if (count($attributes) > self::MAX_ATTRIBUTES) {
            throw new InvalidArgumentException('A service provider is sent at most 256 attributes (spec/saml.md section 7).');
        }
        $names = [];
        foreach ($attributes as $attribute) {
            if (array_key_exists($attribute->name, $names)) {
                throw new InvalidArgumentException('Two attributes of a service provider share a name (spec/saml.md section 6.2 step 1).');
            }
            $names[$attribute->name] = true;
        }
    }

    /**
     * Whether its metadata are verified under the signers it pins, `readSigned()`, rather than trusted by the
     * channel they come through, `readTrusted()` (S-5).
     */
    public function readsSigned(): bool
    {
        return $this->metadataSigners !== [];
    }
}
