<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleLogout;

use Beffroi\Core\Domain\Encoding\Document;
use Beffroi\Core\Exception\InvalidArgumentException;
use function sprintf;

/**
 * What the answer to a LogoutRequest is written from (spec/saml.md S-27, S-34): the service provider that sent it, its
 * ID, the RelayState it carried, and the binding and the URL of the SingleLogoutService its answer goes to, resolved
 * when it was received. Nothing of the principal: the answer names none, so that a chain that keeps it while the other
 * service providers are told (S-32) keeps no NameID.
 */
final readonly class LogoutRequester
{
    /**
     * @param string $answerBinding the URI of the binding of the SingleLogoutService the answer goes to
     * @param string $answerLocation its ResponseLocation, or else its Location (SAML Metadata §2.2.2)
     */
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
     * @throws InvalidArgumentException when a member is missing or is not what a requester holds
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
