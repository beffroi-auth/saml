<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\ServiceProvider;

use Beffroi\Core\Domain\PersonalData\FieldClassificationInterface;
use Beffroi\Core\Domain\PersonalData\Sealed;
use Beffroi\Saml\Domain\Metadata\AcceptedMetadata;

/**
 * The newest metadata document accepted for a service provider of a tenant (spec/saml.md S-6, S-8), kept in
 * beffroi_saml_service_provider and sealed in the family of that table.
 */
final class AcceptedServiceProviderMetadata extends AcceptedMetadata
{
    /**
     * The family the document is sealed in, the name of its table without the prefix of the bundle (decision 0018).
     */
    public const string FAMILY = 'saml_service_provider';

    /**
     * @return array<string, FieldClassificationInterface>
     */
    public static function classifiedFields(): array
    {
        return [
            ...parent::classifiedFields(),
            'document' => new Sealed(self::FAMILY),
        ];
    }
}
