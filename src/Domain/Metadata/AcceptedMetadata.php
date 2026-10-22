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
 * The newest metadata document accepted for a peer of a tenant, whichever its role (spec/saml.md S-6, S-8, S-42): the
 * bytes as they were read, never written again, their `validUntil` to the second, null when they carry none, and the
 * instant they were accepted. One per peer of a role of a tenant, by its entity ID.
 *
 * The rule against a rollback is this row's own (section 6.2 step 6), and it holds a document read under the signers
 * the declaration pins, which an older copy signed by the same key would pass as well: such a document is older than
 * the accepted one when its `validUntil` is earlier, or when it has none and the accepted one has one, and an older
 * document is refused rather than taken. A document its channel vouches for replaces the accepted one whatever its
 * `validUntil`, the channel vouching for the newer reading as it vouched for the older one, so that a document a host
 * held by somebody else wrote with a far `validUntil` is replaced at the next refresh and pins nothing (S-6).
 *
 * Each role keeps its documents in a table of its own, sealed in the family of that table (decision 0018), so the row
 * of a role is a class of its own, which classifies its document under that family and adds nothing else: the rule is
 * written here once for both. What it holds is written from the scope of that class too, when the mapping hydrates a
 * row, which is why it is protected and not private.
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

    /**
     * Whether these are the bytes it holds already: a refresh that reads them again writes nothing.
     */
    public function holds(string $document): bool
    {
        return $this->document === $document;
    }

    /**
     * The document read now takes the place of this one (section 6.2 step 6): whatever its validUntil when its channel
     * vouches for it, when it is not older than this one when it was read under the signers the declaration pins.
     *
     * @throws MetadataRefusedException when the document was read signed and is older than this one (S-6), which is
     *                                  then kept
     * @throws InvalidArgumentException when the document is another entity's: a programming error of the caller
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
     * S-6: a document read signed is older than this one when its validUntil is earlier than this one's, or when it has
     * none and this one has one.
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
     * The validUntil to the second, as its column keeps it: a document read again whose validUntil has a fraction of
     * a second is not older than the one kept without it.
     */
    private static function toTheSecond(?DateTimeImmutable $instant): ?DateTimeImmutable
    {
        return $instant?->setTime((int) $instant->format('G'), (int) $instant->format('i'), (int) $instant->format('s'));
    }

    /**
     * What every row keeps besides its document, which the row of each role classifies, sealed in the family of its
     * table (S-8): an `md:ContactPerson` names people, their electronic addresses and their telephone numbers. The
     * entity ID names a service and is what a peer is found by.
     *
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
