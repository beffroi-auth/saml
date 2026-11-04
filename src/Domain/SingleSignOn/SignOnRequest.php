<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleSignOn;

use Beffroi\Core\Domain\Encoding\Document;
use Beffroi\Core\Exception\InvalidArgumentException;
use DateInterval;
use DateTimeImmutable;
use Exception;
use function sprintf;

final readonly class SignOnRequest
{
    /**
     * Seconds a request waits for its login.
     */
    public const int PENDING = 600;

    private const string TIME = 'Y-m-d\TH:i:s.uP';

    /**
     * @throws InvalidArgumentException when a name it carries is empty
     */
    public function __construct(
        public string $serviceProvider,
        public string $id,
        public string $assertionConsumerService,
        public ?string $relayState,
        public bool $forceAuthn,
        public bool $isPassive,
        public ?string $nameIdFormat,
        public bool $authnContextRequested,
        public DateTimeImmutable $receivedAt,
    ) {
        if ($serviceProvider === '' || $id === '' || $assertionConsumerService === '') {
            throw new InvalidArgumentException('A request names its service provider, its ID and where it is answered (spec/saml.md section 6.4 step 1).');
        }
    }

    public function expiresAt(): DateTimeImmutable
    {
        return $this->receivedAt->add(new DateInterval(sprintf('PT%dS', self::PENDING)));
    }

    /**
     * @return array<string, string|bool|null>
     */
    public function toDocument(): array
    {
        return [
            'service_provider' => $this->serviceProvider,
            'id' => $this->id,
            'assertion_consumer_service' => $this->assertionConsumerService,
            'relay_state' => $this->relayState,
            'force_authn' => $this->forceAuthn,
            'is_passive' => $this->isPassive,
            'name_id_format' => $this->nameIdFormat,
            'authn_context_requested' => $this->authnContextRequested,
            'received_at' => $this->receivedAt->format(self::TIME),
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
        $written = self::required($members->nullableString('received_at'), 'received_at');

        try {
            $receivedAt = new DateTimeImmutable($written);
        } catch (Exception $exception) {
            throw new InvalidArgumentException('The member "received_at" is not when a request was received.', previous: $exception);
        }

        return new self(
            self::required($members->nullableString('service_provider'), 'service_provider'),
            self::required($members->nullableString('id'), 'id'),
            self::required($members->nullableString('assertion_consumer_service'), 'assertion_consumer_service'),
            $members->nullableString('relay_state'),
            self::required($members->nullableBool('force_authn'), 'force_authn'),
            self::required($members->nullableBool('is_passive'), 'is_passive'),
            $members->nullableString('name_id_format'),
            self::required($members->nullableBool('authn_context_requested'), 'authn_context_requested'),
            $receivedAt,
        );
    }

    /**
     * @template T of string|bool
     *
     * @param T|null $value
     *
     * @return T
     *
     * @throws InvalidArgumentException
     */
    private static function required(string|bool|null $value, string $member): string|bool
    {
        return $value ?? throw new InvalidArgumentException(sprintf('A request waiting for a login holds its member "%s".', $member));
    }
}
