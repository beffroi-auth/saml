<?php

declare(strict_types=1);

namespace Beffroi\Saml\Domain\SingleSignOn;

use Beffroi\Core\Domain\Encoding\Base64Url;
use Beffroi\Core\Domain\Identity\Subject;
use Beffroi\Core\Exception\InvalidArgumentException;
use function hash;
use SensitiveParameter;
use function strlen;

/**
 * The persistent identifier of a user at one service provider (spec/saml.md S-13, Core §8.3.7): the SHA-256 of the
 * entity ID of the service provider, the "sub" of the user and the salt of the tenant, each followed by a NUL, in
 * base64url. Computed and never drawn, it is the same at every login, in every worker and after a restore; two service
 * providers get two values nobody relates without the salt, and none of them is the "sub".
 */
final readonly class PersistentNameId
{
    public const string FORMAT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';

    /**
     * Core §8.3.7.
     */
    private const int MAX_LENGTH = 256;

    /**
     * @throws InvalidArgumentException when the value is empty or longer than the format allows
     */
    public function __construct(
        public string $value,
    ) {
        if ($value === '' || strlen($value) > self::MAX_LENGTH) {
            throw new InvalidArgumentException('A persistent identifier is 1 to 256 characters long (Core section 8.3.7).');
        }
    }

    /**
     * @param string $serviceProvider the entity ID of the service provider, as its declaration holds it
     * @param string $salt the secret of the tenant (PersistentIdentifierSaltInterface)
     */
    public static function derive(string $serviceProvider, Subject $subject, #[SensitiveParameter] string $salt): self
    {
        return new self(Base64Url::encode(hash('sha256', $serviceProvider . "\0" . $subject->value . "\0" . $salt . "\0", true)));
    }
}
