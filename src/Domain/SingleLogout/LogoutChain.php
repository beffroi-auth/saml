<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleLogout;

use Beffroi\Core\Domain\PersonalData\ClassifiedFieldsInterface;
use Beffroi\Core\Domain\PersonalData\FieldClassificationInterface;
use Beffroi\Core\Domain\PersonalData\NoPersonalDatum;
use Beffroi\Core\Domain\PersonalData\Reason;
use Beffroi\Core\Domain\Tenant\Tenant;
use DateInterval;
use DateTimeImmutable;
use function hash;
use function hash_equals;
use function sprintf;

/**
 * spec/saml.md S-32
 */
final readonly class LogoutChain implements ClassifiedFieldsInterface
{
    /**
     * Seconds a chain stays open from its last step, the wait of a request for a login (S-18).
     */
    public const int TTL = 600;

    /**
     * @param string $reference the SHA-256 of the reference, digestOf()
     * @param string $secret the SHA-256 of the secret of the browser, LogoutChainSecret::digest()
     */
    public function __construct(
        public string $reference,
        public string $secret,
        public Tenant $tenant,
        public ?string $awaitingRequest,
        public LogoutProgress $progress,
        public DateTimeImmutable $expiresAt,
    ) {
    }

    /**
     * Only the digest is kept, so that a dump of the table resumes no chain.
     */
    public static function digestOf(string $value): string
    {
        return hash('sha256', $value);
    }

    public static function closesAt(DateTimeImmutable $now): DateTimeImmutable
    {
        return $now->add(new DateInterval(sprintf('PT%dS', self::TTL)));
    }

    public function isOpen(DateTimeImmutable $now): bool
    {
        return $now < $this->expiresAt;
    }

    public function isHeldBy(LogoutChainSecret $secret): bool
    {
        return hash_equals($this->secret, $secret->digest());
    }

    /**
     * @return array<string, FieldClassificationInterface>
     */
    public static function classifiedFields(): array
    {
        return [
            'reference' => new NoPersonalDatum(Reason::HASHED),
            'secret' => new NoPersonalDatum(Reason::HASHED),
            'tenant' => new NoPersonalDatum(Reason::THE_TENANT),
            'awaitingRequest' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
            'progress' =>
                new NoPersonalDatum('sessions by their identifiers drawn at random, service providers, which are applications, and where the chain ends: a URI a client registered with the state it drew, or the ID and the RelayState a service provider drew for its own request'),
            'expiresAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
        ];
    }
}
