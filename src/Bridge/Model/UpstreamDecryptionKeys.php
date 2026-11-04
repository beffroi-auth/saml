<?php

declare(strict_types=1);

namespace Beffroi\Saml\Bridge\Model;

use function array_map;
use Beffroi\Core\Domain\Key\TenantKey;
use Beffroi\Core\Domain\Key\UnsealedKey;
use Beffroi\Core\Domain\Tenant\Tenant;
use Beffroi\Core\Exception\InvalidArgumentException;
use Beffroi\Core\Exception\KeyNotFoundException;
use Beffroi\Core\Exception\KmsUnavailableException;
use Beffroi\Core\Exception\RuntimeException;
use Beffroi\Core\Exception\UnsupportedAlgorithmException;
use Beffroi\Core\Port\KeptDecryptionKeyProviderInterface;
use Beffroi\Core\Port\KeyAlgorithmsInterface;
use Beffroi\Core\Port\TenantKeyRepositoryInterface;
use Beffroi\Saml\Bridge\Pki\RsaPrivateKey;
use Beffroi\Saml\Domain\Key\SamlEncryptionAlgorithmInterface;
use Beffroi\Saml\Domain\Key\UpstreamEncryptionKeys;
use Beffroi\Xml\Enc\DecryptionKeyInterface;
use Beffroi\Xml\Enc\Exception\InvalidKey;
use Beffroi\Xml\Enc\PrivateDecryptionKey;

/**
 * spec/saml.md S-66, section 6.13. Its keys are read from the store at each call, so that a key retired since is not
 * among them.
 */
final readonly class UpstreamDecryptionKeys
{
    public function __construct(
        private TenantKeyRepositoryInterface $keys,
        private KeyAlgorithmsInterface $algorithms,
        private KeptDecryptionKeyProviderInterface $opened,
    ) {
    }

    /**
     * @param string $identityProvider the entity ID of the provider whose accepted metadata verify the response
     *
     * @throws KmsUnavailableException
     * @throws KeyNotFoundException when a key retired between the reading of the store and its opening
     * @throws RuntimeException when a key of the provider shares its modulus with another key in service (S-64)
     * @throws InvalidArgumentException when a private half is not the one of its public JWK
     * @throws InvalidKey
     */
    public function of(Tenant $tenant, string $identityProvider): ?DecryptionKeyInterface
    {
        try {
            $algorithm = $this->algorithms->named(SamlEncryptionAlgorithmInterface::NAME_PREFIX . $identityProvider);
        } catch (UnsupportedAlgorithmException) {
            return null;
        }
        if (! $algorithm instanceof SamlEncryptionAlgorithmInterface) {
            return null;
        }
        $kids = array_map(
            static fn (TenantKey $key): string => $key->kid,
            UpstreamEncryptionKeys::of($this->keys->findInService($tenant), $identityProvider)->keys,
        );
        // Asked even with no key, so that the core forgets what it held of a provider whose keys have all retired.
        $opened = $this->opened->keptDecryptionKeys($tenant, $algorithm, $kids);
        if ($opened === []) {
            return null;
        }

        return new ProviderDecryptionKey(array_map(
            static fn (UnsealedKey $key): PrivateDecryptionKey => PrivateDecryptionKey::fromPem(RsaPrivateKey::pem($key)),
            $opened,
        ));
    }
}
