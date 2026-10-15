<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use Beffroi\Saml\Domain\ServiceProvider\ServiceProvider;

/**
 * A service provider a message names (spec/saml.md section 6.3 step 1): its declaration, and its accepted document
 * read back once, what this package reads of it beside the model's role.
 */
final readonly class DeclaredServiceProvider
{
    public function __construct(
        public ServiceProvider $declaration,
        public ReadServiceProvider $read,
    ) {
    }
}
