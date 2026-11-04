<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\ServiceProvider;

use Beffroi\Core\Domain\PersonalData\FieldClassificationInterface;
use Beffroi\Core\Domain\PersonalData\Sealed;
use Beffroi\Saml\Domain\Metadata\AcceptedMetadata;

final class AcceptedServiceProviderMetadata extends AcceptedMetadata
{
    /**
     * The name of its table without the prefix of the application (decision 0018).
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
