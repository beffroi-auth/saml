<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleLogout;

use Beffroi\Core\Domain\Encoding\Document;
use Beffroi\Core\Exception\InvalidArgumentException;
use Symfony\Component\Uid\Uuid;

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
     * @throws InvalidArgumentException
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
