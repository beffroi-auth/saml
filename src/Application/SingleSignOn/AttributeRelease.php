<?php

declare(strict_types=1);

namespace Beffroi\Saml\Application\SingleSignOn;

use function array_key_exists;
use function array_map;
use function array_unique;
use function array_values;
use Beffroi\Core\Domain\Identity\User;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Domain\ServiceProvider\AttributeMapping;
use Beffroi\Saml\Domain\ServiceProvider\ServiceProvider;
use Beffroi\Saml\Domain\SingleSignOn\AttributeValue;
use Beffroi\Saml\Domain\SingleSignOn\ReleasedAttribute;
use Beffroi\Saml\Port\ServedClaimsInterface;
use Psr\Log\LoggerInterface;

/**
 * spec/saml.md S-16, section 6.4 step 6
 *
 * A claim that cannot be sent is logged by service provider, claim and rule, never by its value.
 */
final readonly class AttributeRelease
{
    public function __construct(
        private ServedClaimsInterface $claims,
        private LoggerInterface $logger,
    ) {
    }

    /**
     * @return list<ReleasedAttribute>
     */
    public function of(ServiceProvider $declaration, User $user): array
    {
        if ($declaration->attributes === []) {
            return [];
        }
        $values = $this->claims->of(
            $user,
            array_values(array_unique(array_map(
                static fn (AttributeMapping $mapping): string => $mapping->claim,
                $declaration->attributes,
            ))),
        );
        $released = [];
        foreach ($declaration->attributes as $mapping) {
            if (! array_key_exists($mapping->claim, $values) || $values[$mapping->claim] === null) {
                continue;
            }
            try {
                $attributeValues = AttributeValue::ofClaim($values[$mapping->claim]);
            } catch (InvalidArgumentException $exception) {
                $this->logger->warning('The claim "{claim}" is not sent to the SAML service provider "{service_provider}": {rule}', [
                    'claim' => $mapping->claim,
                    'service_provider' => $declaration->entityId,
                    'rule' => $exception->getMessage(),
                ]);

                continue;
            }
            if ($attributeValues === []) {
                continue;
            }
            $released[] = new ReleasedAttribute($mapping->name, $mapping->nameFormat, $mapping->friendlyName, $attributeValues);
        }

        return $released;
    }
}
