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
use function sprintf;

/**
 * A chain of logout the identity provider plays through the browser (spec/saml.md S-32): kept by the provider, never in
 * a cookie nor a URL, found by the SHA-256 of the reference its own pages hand on and by the ID of its outstanding
 * request, open ten minutes from its last step, taken by the one request that plays the next step.
 */
final readonly class LogoutChain implements ClassifiedFieldsInterface
{
    /**
     * Seconds a chain stays open from its last step, the wait of a request for a login (S-18, section 7).
     */
    public const int TTL = 600;

    /**
     * @param string $reference the SHA-256 of the reference, digestOf()
     * @param string|null $awaitingRequest the ID of the LogoutRequest whose answer the chain waits for
     */
    public function __construct(
        public string $reference,
        public Tenant $tenant,
        public ?string $awaitingRequest,
        public LogoutProgress $progress,
        public DateTimeImmutable $expiresAt,
    ) {
    }

    /**
     * What is kept of a reference: its SHA-256, in hexadecimal, so that a dump of the table resumes no chain.
     */
    public static function digestOf(string $reference): string
    {
        return hash('sha256', $reference);
    }

    /**
     * When a chain written at $now closes (S-32).
     */
    public static function closesAt(DateTimeImmutable $now): DateTimeImmutable
    {
        return $now->add(new DateInterval(sprintf('PT%dS', self::TTL)));
    }

    /**
     * A chain past its ten minutes is closed: nothing resumes it, no answer is read for it.
     */
    public function isOpen(DateTimeImmutable $now): bool
    {
        return $now < $this->expiresAt;
    }

    /**
     * @return array<string, FieldClassificationInterface>
     */
    public static function classifiedFields(): array
    {
        return [
            'reference' => new NoPersonalDatum(Reason::HASHED),
            'tenant' => new NoPersonalDatum(Reason::THE_TENANT),
            'awaitingRequest' => new NoPersonalDatum(Reason::DRAWN_AT_RANDOM),
            'progress' =>
                new NoPersonalDatum('sessions by their identifiers drawn at random, service providers, which are applications, and where the chain ends: a URI a client registered with the state it drew, or the ID and the RelayState a service provider drew for its own request'),
            'expiresAt' => new NoPersonalDatum(Reason::NAMES_NO_PERSON),
        ];
    }
}
