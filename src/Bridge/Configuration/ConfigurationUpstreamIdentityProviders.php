<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Configuration;

use function array_values;
use Beffroi\Core\Domain\Identity\EmailDomain;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Bridge\Model\ModelEntityId;
use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml\Domain\Metadata\MetadataLocation;
use Beffroi\Saml\Domain\Upstream\GroupMapping;
use Beffroi\Saml\Domain\Upstream\ProfileAttribute;
use Beffroi\Saml\Domain\Upstream\UpstreamIdentityProvider;
use Beffroi\Saml\Port\ProfileClaimsInterface;
use Beffroi\Saml\Port\UpstreamIdentityProvidersInterface;
use function in_array;
use function is_array;
use function sprintf;

/**
 * spec/saml.md S-42, S-44, S-45, section 5.7, section 6.10 step 1
 */
final readonly class ConfigurationUpstreamIdentityProviders implements UpstreamIdentityProvidersInterface
{
    /**
     * @var array<string, UpstreamIdentityProvider>
     */
    private array $identityProviders;

    /**
     * @param array<array-key, mixed> $definitions by entity ID
     *
     * @throws InvalidArgumentException when a declaration does not hold together, or two declare one domain
     */
    public function __construct(
        private string $tenantSlug,
        array $definitions,
        ProfileClaimsInterface $claims,
    ) {
        $held = $claims->names();
        $identityProviders = [];
        $answering = [];
        foreach ($definitions as $entityId => $definition) {
            $entityId = (string) $entityId;
            try {
                $identityProvider = self::identityProvider($entityId, $definition, $held);
            } catch (InvalidArgumentException $exception) {
                throw new InvalidArgumentException(sprintf('The identity provider "%s": %s', $entityId, $exception->getMessage()), 0, $exception);
            }
            foreach ($identityProvider->domains as $domain) {
                if (isset($answering[$domain->value])) {
                    throw new InvalidArgumentException(sprintf(
                        'The domain "%s" is declared by the identity providers "%s" and "%s", and a domain answers to one provider (spec/saml.md S-44).',
                        $domain->value,
                        $answering[$domain->value],
                        $entityId,
                    ));
                }
                $answering[$domain->value] = $entityId;
            }
            $identityProviders[$entityId] = $identityProvider;
        }
        $this->identityProviders = $identityProviders;
    }

    public function of(Tenant $tenant): array
    {
        return $tenant->slug === $this->tenantSlug ? array_values($this->identityProviders) : [];
    }

    public function find(Tenant $tenant, string $entityId): ?UpstreamIdentityProvider
    {
        return $tenant->slug === $this->tenantSlug ? $this->identityProviders[$entityId] ?? null : null;
    }

    /**
     * @param list<string> $held the claims the profile of a person holds
     *
     * @throws InvalidArgumentException
     */
    private static function identityProvider(string $entityId, mixed $definition, array $held): UpstreamIdentityProvider
    {
        if (! is_array($definition)) {
            throw new InvalidArgumentException('a declaration is a map (spec/saml.md section 5.7).');
        }
        $signers = [];
        foreach (DeclarationMembers::list($definition, 'metadata_signers') as $signer) {
            $signers[] = new Certificate(DeclarationMembers::string($signer, 'metadata_signers'));
        }
        $domains = [];
        foreach (DeclarationMembers::list($definition, 'domains') as $domain) {
            $domains[] = new EmailDomain(DeclarationMembers::string($domain, 'domains'));
        }
        $profile = [];
        foreach (DeclarationMembers::map($definition, 'profile') as $attribute => $claim) {
            $filled = new ProfileAttribute((string) $attribute, DeclarationMembers::string($claim, 'profile'));
            if (! in_array($filled->claim, $held, true)) {
                throw new InvalidArgumentException(sprintf(
                    'the attribute "%s" fills the claim "%s", which the profile of a person does not hold in this deployment (spec/saml.md S-45).',
                    $filled->name,
                    $filled->claim,
                ));
            }
            $profile[] = $filled;
        }
        $subject = $definition['subject_attribute'] ?? null;
        $addressParameter = $definition['address_parameter'] ?? null;

        return new UpstreamIdentityProvider(
            ModelEntityId::ofIdentityProvider($entityId),
            new MetadataLocation(DeclarationMembers::string($definition['metadata'] ?? null, 'metadata')),
            $signers,
            $domains,
            DeclarationMembers::string($definition['email_attribute'] ?? null, 'email_attribute'),
            $profile,
            $subject === null ? null : DeclarationMembers::string($subject, 'subject_attribute'),
            self::groups($definition['groups'] ?? null),
            DeclarationMembers::boolean($definition, 'require_encrypted_assertions', false),
            $addressParameter === null ? null : DeclarationMembers::string($addressParameter, 'address_parameter'),
        );
    }

    /**
     * @throws InvalidArgumentException
     */
    private static function groups(mixed $definition): ?GroupMapping
    {
        if ($definition === null) {
            return null;
        }
        if (! is_array($definition)) {
            throw new InvalidArgumentException('"groups" is a map (spec/saml.md section 5.7).');
        }
        $groups = [];
        foreach (DeclarationMembers::map($definition, 'map') as $value => $group) {
            $groups[$value] = DeclarationMembers::string($group, 'map');
        }

        return new GroupMapping(DeclarationMembers::string($definition['attribute'] ?? null, 'attribute'), $groups);
    }
}
