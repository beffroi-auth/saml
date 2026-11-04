<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleLogout;

use Beffroi\Core\Domain\Encoding\Document;
use Beffroi\Core\Exception\InvalidArgumentException;
use function sprintf;

/**
 * It holds nothing of the principal, so that a chain that keeps it while the other service providers are told keeps no
 * NameID (S-32).
 */
final readonly class LogoutRequester
{
    public function __construct(
        public string $serviceProvider,
        public string $requestId,
        public ?string $relayState,
        public string $answerBinding,
        public string $answerLocation,
    ) {
    }

    /**
     * @return array<string, string|null>
     */
    public function toDocument(): array
    {
        return [
            'service_provider' => $this->serviceProvider,
            'request_id' => $this->requestId,
            'relay_state' => $this->relayState,
            'answer_binding' => $this->answerBinding,
            'answer_location' => $this->answerLocation,
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

        return new self(
            self::required($members->nullableString('service_provider'), 'service_provider'),
            self::required($members->nullableString('request_id'), 'request_id'),
            $members->nullableString('relay_state'),
            self::required($members->nullableString('answer_binding'), 'answer_binding'),
            self::required($members->nullableString('answer_location'), 'answer_location'),
        );
    }

    /**
     * @throws InvalidArgumentException
     */
    private static function required(?string $value, string $name): string
    {
        return $value ?? throw new InvalidArgumentException(sprintf('The member "%s" of a logout requester is missing.', $name));
    }
}
