<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Replay;

use Beffroi\Core\Domain\PersonalData\ClassifiedFieldsInterface;
use Beffroi\Core\Domain\PersonalData\FieldClassificationInterface;
use Beffroi\Core\Domain\PersonalData\NoPersonalDatum;
use Beffroi\Core\Domain\PersonalData\Reason;
use Beffroi\Core\Domain\Tenant\Tenant;
use DateTimeImmutable;
use function hash;

/**
 * An assertion or a logout message the model accepted (spec/saml.md S-23, S-53), remembered until the window in which
 * it would accept it again has closed (model.md M-11): keyed by the SHA-256 of its tenant, its issuer and its ID, each
 * followed by a NUL, which none of them holds, so that a key is 64 hexadecimal digits whatever the length of the
 * entity ID.
 */
final readonly class RememberedMessage implements ClassifiedFieldsInterface
{
    public function __construct(
        public string $key,
        public Tenant $tenant,
        public DateTimeImmutable $expiresAt,
    ) {
    }

    /**
     * The key of the message $id of $issuer under $tenant.
     */
    public static function keyOf(Tenant $tenant, string $issuer, string $id): string
    {
        return hash('sha256', $tenant->id->toRfc4122() . "\0" . $issuer . "\0" . $id . "\0");
    }

    /**
     * @return array<string, FieldClassificationInterface>
     */
    public static function classifiedFields(): array
    {
        return [
            'key' => new NoPersonalDatum(Reason::HASHED),
            'tenant' => new NoPersonalDatum(Reason::THE_TENANT),
            'expiresAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
        ];
    }
}
