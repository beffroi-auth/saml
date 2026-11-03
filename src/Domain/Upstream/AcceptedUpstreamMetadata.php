<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Upstream;

use Beffroi\Core\Domain\PersonalData\FieldClassificationInterface;
use Beffroi\Core\Domain\PersonalData\Sealed;
use Beffroi\Saml\Domain\Metadata\AcceptedMetadata;

/**
 * The newest metadata document accepted for an upstream identity provider of a tenant (spec/saml.md S-6, S-8, S-42),
 * kept in beffroi_saml_upstream_identity_provider and sealed in the family of that table: its md:ContactPerson names
 * people as a service provider's does.
 */
final class AcceptedUpstreamMetadata extends AcceptedMetadata
{
    /**
     * The family the document is sealed in, the name of its table without the prefix of the application (decision 0018).
     */
    public const string FAMILY = 'saml_upstream_identity_provider';

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
