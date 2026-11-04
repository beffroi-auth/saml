<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Configuration;

use function array_values;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\Metadata\Certificate;
use Beffroi\Saml\Domain\ServiceProvider\AttributeMapping;
use Beffroi\Saml\Domain\ServiceProvider\AttributeNameFormat;
use Beffroi\Saml\Domain\Metadata\MetadataLocation;
use Beffroi\Saml\Domain\ServiceProvider\ServiceProvider;
use Beffroi\Saml\Port\ServedClaimsInterface;
use Beffroi\Saml\Port\ServiceProvidersInterface;
use function in_array;
use function is_array;
use function sprintf;

/**
 * spec/saml.md S-5, S-16, section 5.2, section 6.2 step 1
 */
final readonly class ConfigurationServiceProviders implements ServiceProvidersInterface
{
    /**
     * @var array<string, ServiceProvider>
     */
    private array $serviceProviders;

    /**
     * @param array<array-key, mixed> $definitions by entity ID
     *
     * @throws InvalidArgumentException when a declaration does not hold together
     */
    public function __construct(
        private string $tenantSlug,
        array $definitions,
        ServedClaimsInterface $claims,
    ) {
        $served = $claims->names();
        $serviceProviders = [];
        foreach ($definitions as $entityId => $definition) {
            $entityId = (string) $entityId;
            try {
                $serviceProviders[$entityId] = self::serviceProvider($entityId, $definition, $served);
            } catch (InvalidArgumentException $exception) {
                throw new InvalidArgumentException(sprintf('The service provider "%s": %s', $entityId, $exception->getMessage()), 0, $exception);
            }
        }
        $this->serviceProviders = $serviceProviders;
    }

    public function of(Tenant $tenant): array
    {
        return $tenant->slug === $this->tenantSlug ? array_values($this->serviceProviders) : [];
    }

    public function find(Tenant $tenant, string $entityId): ?ServiceProvider
    {
        return $tenant->slug === $this->tenantSlug ? $this->serviceProviders[$entityId] ?? null : null;
    }

    /**
     * @param list<string> $served the claims the provider serves
     *
     * @throws InvalidArgumentException
     */
    private static function serviceProvider(string $entityId, mixed $definition, array $served): ServiceProvider
    {
        if (! is_array($definition)) {
            throw new InvalidArgumentException('a declaration is a map (spec/saml.md section 5.2).');
        }
        $signers = [];
        foreach (DeclarationMembers::list($definition, 'metadata_signers') as $signer) {
            $signers[] = new Certificate(DeclarationMembers::string($signer, 'metadata_signers'));
        }
        $attributes = [];
        foreach (DeclarationMembers::map($definition, 'attributes') as $name => $attribute) {
            $mapping = self::attribute((string) $name, $attribute);
            if (! in_array($mapping->claim, $served, true)) {
                throw new InvalidArgumentException(sprintf(
                    'the attribute "%s" maps the claim "%s", which this provider does not serve (spec/saml.md S-16).',
                    $mapping->name,
                    $mapping->claim,
                ));
            }
            $attributes[] = $mapping;
        }

        return new ServiceProvider(
            $entityId,
            new MetadataLocation(DeclarationMembers::string($definition['metadata'] ?? null, 'metadata')),
            $signers,
            $attributes,
            DeclarationMembers::boolean($definition, 'encrypt_assertions', false),
            DeclarationMembers::boolean($definition, 'signs_authn_requests', true),
        );
    }

    /**
     * @throws InvalidArgumentException
     */
    private static function attribute(string $name, mixed $definition): AttributeMapping
    {
        if (! is_array($definition)) {
            throw new InvalidArgumentException('an attribute is a map (spec/saml.md section 5.2).');
        }
        $format = DeclarationMembers::string($definition['name_format'] ?? 'uri', 'name_format');
        $friendlyName = $definition['friendly_name'] ?? null;

        return new AttributeMapping(
            DeclarationMembers::string($definition['claim'] ?? null, 'claim'),
            $name,
            AttributeNameFormat::named($format) ?? throw new InvalidArgumentException(sprintf(
                '"%s" is not a name format of Core section 8.2: uri, basic or unspecified.',
                $format,
            )),
            $friendlyName === null ? null : DeclarationMembers::string($friendlyName, 'friendly_name'),
        );
    }
}
