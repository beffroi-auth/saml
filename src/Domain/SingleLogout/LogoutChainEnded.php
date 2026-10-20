<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleLogout;

use Beffroi\Saml\Domain\SingleSignOn\PostedForm;

/**
 * Nothing left to tell (spec/saml.md S-34): the answer to the service provider that asked, or, when nobody is to be
 * answered, where the browser goes, the URL the starter of the chain named, or null for the page that says it is
 * signed out. Whatever it carries, the chain is over, and the browser holds nothing of it any more (S-32).
 */
final readonly class LogoutChainEnded
{
    /**
     * @param string|null $continueTo where the browser goes when nobody is to be answered
     * @param PostedForm|RedirectedMessage|null $answer the LogoutResponse to the service provider that asked, as the
     *                                                  browser carries it
     */
    public function __construct(
        public ?string $continueTo,
        public PostedForm|RedirectedMessage|null $answer = null,
    ) {
    }
}
