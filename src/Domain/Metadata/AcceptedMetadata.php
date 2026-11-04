<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\Metadata;

use Beffroi\Core\Domain\PersonalData\ClassifiedFieldsInterface;
use Beffroi\Core\Domain\PersonalData\FieldClassificationInterface;
use Beffroi\Core\Domain\PersonalData\NoPersonalDatum;
use Beffroi\Core\Domain\PersonalData\Reason;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Saml\Exception\MetadataRefusedException;
use DateTimeImmutable;
use Symfony\Component\Uid\Uuid;

/**
 * spec/saml.md S-6, S-8, S-42. Its properties are protected(set): the mapping of each role hydrates a row from the
 * scope of its own class.
 */
abstract class AcceptedMetadata implements ClassifiedFieldsInterface
{
    /**
     * @throws InvalidArgumentException when the document is empty
     */
    public function __construct(
        public readonly Uuid $id,
        public readonly Tenant $tenant,
        public readonly string $entityId,
        public protected(set) string $document,
        public protected(set) ?DateTimeImmutable $validUntil,
        public protected(set) DateTimeImmutable $acceptedAt,
    ) {
        if ($document === '') {
            throw new InvalidArgumentException('An accepted metadata document holds the bytes that were read (spec/saml.md S-8).');
        }
        $this->validUntil = self::toTheSecond($validUntil);
    }

    public function holds(string $document): bool
    {
        return $this->document === $document;
    }

    /**
     * Section 6.2 step 6. A document its channel vouches for replaces this one whatever its validUntil, so that one
     * written with a far validUntil by whoever held the host pins nothing.
     *
     * @throws MetadataRefusedException when the document was read signed and is older than this one (S-6)
     * @throws InvalidArgumentException when the document is another entity's
     */
    public function replaceWith(PeerMetadataInterface $metadata, string $document, DateTimeImmutable $at): void
    {
        if ($metadata->entityId !== $this->entityId) {
            throw new InvalidArgumentException('An accepted metadata document is replaced by a document of its own entity (spec/saml.md section 6.2 step 6).');
        }
        if ($metadata->readSigned) {
            $this->refuseOlder($metadata->validUntil);
        }
        if ($document === '') {
            throw new InvalidArgumentException('An accepted metadata document holds the bytes that were read (spec/saml.md S-8).');
        }
        $this->document = $document;
        $this->validUntil = self::toTheSecond($metadata->validUntil);
        $this->acceptedAt = $at;
    }

    /**
     * S-6
     *
     * @throws MetadataRefusedException
     */
    private function refuseOlder(?DateTimeImmutable $validUntil): void
    {
        if (! $this->validUntil instanceof DateTimeImmutable) {
            return;
        }
        if (! $validUntil instanceof DateTimeImmutable) {
            throw new MetadataRefusedException('The metadata carry no validUntil where the document accepted carries one, so they cannot be shown not to be older (spec/saml.md S-6).');
        }
        if ($validUntil < $this->validUntil) {
            throw new MetadataRefusedException('The metadata are valid until an earlier instant than the document accepted, so they are older (spec/saml.md S-6).');
        }
    }

    /**
     * As its column keeps it: a document read again whose validUntil has a fraction of a second is not older than
     * the one kept without it.
     */
    private static function toTheSecond(?DateTimeImmutable $instant): ?DateTimeImmutable
    {
        return $instant?->setTime((int) $instant->format('G'), (int) $instant->format('i'), (int) $instant->format('s'));
    }

    /**
     * @return array<string, FieldClassificationInterface>
     */
    public static function classifiedFields(): array
    {
        return [
            'id' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
            'tenant' => new NoPersonalDatum(Reason::THE_TENANT),
            'entityId' => new NoPersonalDatum('names a service provider or an identity provider, an application and never a person'),
            'validUntil' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
            'acceptedAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
        ];
    }
}
