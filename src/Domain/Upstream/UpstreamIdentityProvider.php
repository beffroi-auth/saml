<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Upstream;

use function array_key_exists;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml\Domain\Metadata\Lexical;
use Beffroi\Saml\Domain\Metadata\MetadataLocation;
use Beffroi\Saml\Domain\Metadata\PeerInterface;
use function count;
use function sprintf;

/**
 * An upstream identity provider of a tenant as the deployment declares it (spec/saml.md S-42, section 5.7): an
 * identity provider whose assertions the service provider of the tenant receives. Its entity ID, where its metadata
 * are read from and who signs them; the e-mail domains it answers for (S-44); and what an assertion of it is read for
 * (S-45): the attribute of the e-mail, the attributes that fill the profile, the attribute that names a person when
 * the NameID is not persistent, and the groups; and whether its assertions must arrive encrypted (S-67), which the
 * assertion consumer service applies (issue #784). Never registered by a request nor through a page: a declaration goes
 * away when its block does. Its entity ID is held to the rule of the model where the declaration is read
 * (ModelEntityId), the model being no dependency of the domain.
 */
final readonly class UpstreamIdentityProvider implements PeerInterface
{
    /**
     * The `maxVerificationKeys` of Dsig, which `readSigned()` hands the signers to (section 7).
     */
    public const int MAX_METADATA_SIGNERS = 16;

    /**
     * The domains of one organisation, which a declaration names one by one (section 7).
     */
    public const int MAX_DOMAINS = 256;

    /**
     * @param list<Certificate> $metadataSigners the certificates the metadata are verified under, none when the channel is trusted
     * @param list<EmailDomain> $domains the domains it answers for, one at least
     * @param list<ProfileAttribute> $profile the attributes that fill the profile, one per claim
     * @param bool $requireEncryptedAssertions whether an assertion of it in clear is refused (S-67)
     *
     * @throws InvalidArgumentException when the declaration does not hold together (section 6.10 step 1)
     */
    public function __construct(
        public string $entityId,
        public MetadataLocation $metadata,
        public array $metadataSigners,
        public array $domains,
        public string $emailAttribute,
        public array $profile = [],
        public ?string $subjectAttribute = null,
        public ?GroupMapping $groups = null,
        public bool $requireEncryptedAssertions = false,
    ) {
        if (count($metadataSigners) > self::MAX_METADATA_SIGNERS) {
            throw new InvalidArgumentException('An identity provider pins at most 16 signers of its metadata (spec/saml.md section 7).');
        }
        self::assertDomains($domains);
        if (! Lexical::isName($emailAttribute)) {
            throw new InvalidArgumentException('The attribute of the e-mail is not empty, holds no whitespace and is at most 1024 characters (spec/saml.md S-45).');
        }
        self::assertProfile($profile);
        if ($subjectAttribute !== null && ! Lexical::isName($subjectAttribute)) {
            throw new InvalidArgumentException('The attribute of the subject is not empty, holds no whitespace and is at most 1024 characters (spec/saml.md S-45).');
        }
        if ($subjectAttribute === $emailAttribute) {
            throw new InvalidArgumentException('The attribute of the subject is the attribute of the e-mail, and an address is given again to another person (spec/saml.md S-45).');
        }
    }

    /**
     * S-42: an upstream identity provider is never the tenant itself, declared under the entity ID of the identity
     * provider of the tenant, whose assertions its service provider would then take for another's, or under the
     * entity ID of its service provider, one entity ID naming two roles (S-38). Compared exactly, as entity IDs are.
     *
     * @param string|null $identityProvider the entity ID of the identity provider of the tenant, null when unknown yet
     * @param string|null $serviceProvider the entity ID of the service provider of the tenant, null when unknown yet
     *
     * @throws InvalidArgumentException when the entity ID is one of the tenant's own
     */
    public static function assertNotTheTenant(string $entityId, ?string $identityProvider, ?string $serviceProvider): void
    {
        if ($entityId === $identityProvider) {
            throw new InvalidArgumentException(sprintf(
                'The identity provider "%s" is declared under the entity ID of the identity provider of the tenant, and a tenant is never upstream of itself (spec/saml.md S-42).',
                $entityId,
            ));
        }
        if ($entityId === $serviceProvider) {
            throw new InvalidArgumentException(sprintf(
                'The identity provider "%s" is declared under the entity ID of the service provider of the tenant, and a tenant is never upstream of itself (spec/saml.md S-42).',
                $entityId,
            ));
        }
    }

    /**
     * Whether its metadata are verified under the signers it pins, `readSigned()`, rather than trusted by the
     * channel they come through, `readTrusted()` (S-42).
     */
    public function readsSigned(): bool
    {
        return $this->metadataSigners !== [];
    }

    /**
     * @param list<EmailDomain> $domains
     *
     * @throws InvalidArgumentException
     */
    private static function assertDomains(array $domains): void
    {
        if ($domains === []) {
            throw new InvalidArgumentException('An identity provider answers for one e-mail domain at least (spec/saml.md S-44).');
        }
        if (count($domains) > self::MAX_DOMAINS) {
            throw new InvalidArgumentException('An identity provider answers for 256 e-mail domains at most (spec/saml.md section 7).');
        }
        $declared = [];
        foreach ($domains as $domain) {
            if (array_key_exists($domain->value, $declared)) {
                throw new InvalidArgumentException(sprintf('The domain "%s" is declared twice (spec/saml.md S-44).', $domain->value));
            }
            $declared[$domain->value] = true;
        }
    }

    /**
     * @param list<ProfileAttribute> $profile
     *
     * @throws InvalidArgumentException
     */
    private static function assertProfile(array $profile): void
    {
        $names = [];
        $claims = [];
        foreach ($profile as $attribute) {
            if (array_key_exists($attribute->name, $names)) {
                throw new InvalidArgumentException(sprintf('The attribute "%s" fills the profile twice (spec/saml.md S-45).', $attribute->name));
            }
            if (array_key_exists($attribute->claim, $claims)) {
                throw new InvalidArgumentException(sprintf('The claim "%s" is filled by two attributes (spec/saml.md S-45).', $attribute->claim));
            }
            $names[$attribute->name] = true;
            $claims[$attribute->claim] = true;
        }
    }
}
