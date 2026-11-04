<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleLogout;

use function array_map;
use function array_slice;
use Beffroi\Core\Domain\Encoding\Document;
use Beffroi\Core\Exception\InvalidArgumentException;
use function is_string;
use Symfony\Component\Uid\Uuid;

final readonly class LogoutProgress
{
    /**
     * @param list<Uuid> $sessions
     * @param list<LogoutHop> $hops in the order they are told
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

    public function next(): ?LogoutHop
    {
        return $this->hops[0] ?? null;
    }

    public function withoutNext(): self
    {
        return new self($this->sessions, array_slice($this->hops, 1), $this->awaitingFrom, $this->partial, $this->requester, $this->continueTo);
    }

    public function awaiting(string $serviceProvider): self
    {
        return new self($this->sessions, $this->hops, $serviceProvider, $this->partial, $this->requester, $this->continueTo);
    }

    public function answered(bool $success): self
    {
        return new self($this->sessions, $this->hops, null, $this->partial || ! $success, $this->requester, $this->continueTo);
    }

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
     * @throws InvalidArgumentException
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
