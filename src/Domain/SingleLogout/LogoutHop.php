<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleLogout;

use Beffroi\Core\Domain\Encoding\Document;
use Beffroi\Core\Exception\InvalidArgumentException;
use Symfony\Component\Uid\Uuid;

/**
 * A service provider left to tell of an ended session (spec/saml.md S-30): the session by its ID, which the request
 * names as its SessionIndex and whose user its NameID is computed for (S-31), and the entity ID of the service
 * provider.
 */
final readonly class LogoutHop
{
    public function __construct(
        public Uuid $session,
        public string $serviceProvider,
    ) {
    }

    /**
     * @return array<string, string>
     */
    public function toDocument(): array
    {
        return [
            'session' => $this->session->toRfc4122(),
            'service_provider' => $this->serviceProvider,
        ];
    }

    /**
     * @param array<array-key, mixed> $document
     *
     * @throws InvalidArgumentException when a member is missing or is not what a hop holds
     */
    public static function fromDocument(array $document): self
    {
        $members = new Document($document);
        $session = $members->nullableString('session');
        if ($session === null || ! Uuid::isValid($session)) {
            throw new InvalidArgumentException('The member "session" of a logout hop is not the ID of a session.');
        }

        return new self(
            Uuid::fromString($session),
            $members->nullableString('service_provider') ?? throw new InvalidArgumentException('The member "service_provider" of a logout hop is missing.'),
        );
    }
}
