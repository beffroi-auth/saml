<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Upstream;

use function array_key_exists;
use Beffroi\Core\Domain\Identity\EmailAddress;
use Beffroi\Core\Domain\Identity\EmailDomain;
use Beffroi\Core\Domain\Identity\Profile;
use Beffroi\Core\Domain\Identity\UpstreamProvider;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml\Domain\Metadata\Lexical;
use Beffroi\Saml\Domain\Metadata\MetadataLocation;
use Beffroi\Saml\Domain\Metadata\PeerInterface;
use function count;
use function sprintf;

/**
 * Its entity ID is held to the rule of the model where the declaration is read (ModelEntityId), the domain not
 * depending on the model.
 */
final readonly class UpstreamIdentityProvider implements PeerInterface
{
    /**
     * The `maxVerificationKeys` of Dsig, which `readSigned()` hands the signers to (section 7).
     */
    public const int MAX_METADATA_SIGNERS = 16;

    public const int MAX_DOMAINS = 256;

    /**
     * @param list<Certificate> $metadataSigners none when the channel is trusted
     * @param list<EmailDomain> $domains
     * @param list<ProfileAttribute> $profile
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
        public ?string $addressParameter = null,
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
        if ($addressParameter !== null) {
            AddressHint::assertParameter($addressParameter);
        }
    }

    /**
     * S-38, S-42
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
     * S-60. A telephone number an attribute fills is left out, being no claim of the profile of the core
     * (Profile::claims()): the sign-in reads it apart.
     */
    public function provider(): UpstreamProvider
    {
        $held = Profile::empty()->claims();
        $claims = [];
        foreach ($this->profile as $attribute) {
            if (array_key_exists($attribute->claim, $held)) {
                $claims[] = $attribute->claim;
            }
        }

        return new UpstreamProvider($this->entityId, $this->domains, $claims);
    }

    /**
     * S-68: none unless this provider answers for the domain of the address, so that the address goes to no other
     * provider. A hint that cannot be built is no refusal: the request goes without it.
     */
    public function addressHint(?string $address): ?AddressHint
    {
        if ($this->addressParameter === null || $address === null) {
            return null;
        }
        try {
            $domain = EmailDomain::ofAddress($address);
            $read = EmailAddress::ofAnySpelling($address);
        } catch (InvalidArgumentException) {
            return null;
        }

        return $this->provider()->answersFor($domain) ? new AddressHint($this->addressParameter, $read) : null;
    }

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
