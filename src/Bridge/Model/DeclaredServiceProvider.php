<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use Beffroi\Saml\Domain\ServiceProvider\ServiceProvider;

/**
 * spec/saml.md section 6.3 step 1
 */
final readonly class DeclaredServiceProvider
{
    public function __construct(
        public ServiceProvider $declaration,
        public ReadServiceProvider $read,
    ) {
    }
}
