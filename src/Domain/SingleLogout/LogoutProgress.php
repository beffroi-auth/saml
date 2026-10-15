<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleLogout;

use function array_map;
use function array_slice;
use Beffroi\Core\Domain\Encoding\Document;
use Beffroi\Core\Exception\InvalidArgumentException;
use function is_string;
use Symfony\Component\Uid\Uuid;

/**
 * Where a chain of logout stands (spec/saml.md S-32): the IDs of the sessions it is about, the service providers left
 * to tell (S-30), the one the outstanding request went to, whether one told so far did not answer Success or was passed
 * over, and where it ends (S-34): the answer to the service provider that asked, or the URL its starter names. What the
 * column of the chain holds is this document, written and read here.
 */
final readonly class LogoutProgress
{
    /**
     * @param list<Uuid> $sessions the sessions ended, the ones the page of S-35 is about
     * @param list<LogoutHop> $hops the service providers left to tell, in their order
     * @param string|null $awaitingFrom the service provider the outstanding request went to
     * @param bool $partial whether a service provider told did not answer Success, or was passed over
     * @param LogoutRequester|null $requester the service provider whose request started the logout, answered last
     * @param string|null $continueTo where the browser goes at the end when no service provider is to be answered
     */
    public function __construct(
        public array $sessions,
        public array $hops,
        public ?string $awaitingFrom,
        public bool $partial,
        public ?LogoutRequester $requester,
        public ?string $continueTo,
    ) {
    }

    /**
     * The next service provider to tell, null when every one has been.
     */
    public function next(): ?LogoutHop
    {
        return $this->hops[0] ?? null;
    }

    /**
     * The next service provider taken off, as it is told or passed over.
     */
    public function withoutNext(): self
    {
        return new self($this->sessions, array_slice($this->hops, 1), $this->awaitingFrom, $this->partial, $this->requester, $this->continueTo);
    }

    /**
     * A request sent to $serviceProvider, its answer awaited (S-33).
     */
    public function awaiting(string $serviceProvider): self
    {
        return new self($this->sessions, $this->hops, $serviceProvider, $this->partial, $this->requester, $this->continueTo);
    }

    /**
     * The answer of the service provider awaited, Success or not (S-33).
     */
    public function answered(bool $success): self
    {
        return new self($this->sessions, $this->hops, null, $this->partial || ! $success, $this->requester, $this->continueTo);
    }

    /**
     * A service provider passed over, which counts as one that did not answer Success (S-30).
     */
    public function passedOver(): self
    {
        return new self($this->sessions, $this->hops, $this->awaitingFrom, true, $this->requester, $this->continueTo);
    }

    /**
     * @return array<string, mixed>
     */
    public function toDocument(): array
    {
        return [
            'sessions' => array_map(static fn (Uuid $session): string => $session->toRfc4122(), $this->sessions),
            'hops' => array_map(static fn (LogoutHop $hop): array => $hop->toDocument(), $this->hops),
            'awaiting_from' => $this->awaitingFrom,
            'partial' => $this->partial,
            'requester' => $this->requester?->toDocument(),
            'continue_to' => $this->continueTo,
        ];
    }

    /**
     * @param array<array-key, mixed> $document
     *
     * @throws InvalidArgumentException when a member is missing or is not what a chain holds
     */
    public static function fromDocument(array $document): self
    {
        $members = new Document($document);
        $sessions = [];
        foreach ($members->entries('sessions') as $session) {
            if (! is_string($session) || ! Uuid::isValid($session)) {
                throw new InvalidArgumentException('A member of "sessions" of a chain is not the ID of a session.');
            }
            $sessions[] = Uuid::fromString($session);
        }
        $hops = [];
        foreach ($members->entries('hops') as $hop) {
            $hops[] = LogoutHop::fromDocument(Document::of($hop, 'hop of a chain')->members);
        }
        $requester = $members->nested('requester');

        return new self(
            $sessions,
            $hops,
            $members->nullableString('awaiting_from'),
            $members->nullableBool('partial') ?? throw new InvalidArgumentException('The member "partial" of a chain is missing.'),
            $requester === null ? null : LogoutRequester::fromDocument($requester),
            $members->nullableString('continue_to'),
        );
    }
}
