<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleLogout;

final readonly class SignOutRequest
{
    /**
     * @param list<string> $sessionIndexes
     */
    public function __construct(
        public string $serviceProvider,
        public string $id,
        public string $nameId,
        public string $nameIdFormat,
        public ?string $nameQualifier,
        public ?string $spNameQualifier,
        public array $sessionIndexes,
        public ?string $relayState,
        public string $answerBinding,
        public string $answerLocation,
    ) {
    }

    public function requester(): LogoutRequester
    {
        return new LogoutRequester($this->serviceProvider, $this->id, $this->relayState, $this->answerBinding, $this->answerLocation);
    }
}
