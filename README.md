# beffroi/saml

Part of [beffroi/framework](https://github.com/beffroi-php/beffroi), developed in `src/saml` of that monorepo; this repository is
its read-only split. Issues and pull requests go to the monorepo.

The SAML 2.0 module of the identity provider: the profile written on
[`beffroi/saml2-model`](https://github.com/beffroi-php/saml2-model) and
[`beffroi/saml2-bindings`](https://github.com/beffroi-php/saml2-bindings) for the tenants, the users and the sessions
of [`beffroi/core`](https://github.com/beffroi-php/core): the identity provider and the service providers of a tenant,
their metadata, the attributes mapped from the claims, the `NameID` derived from the `sub`, Single Logout on the
session of the core. Pure PHP, in the four layers of the identity provider's packages; the HTTP request is the
bundle's.

[`spec/saml.md`](spec/saml.md) is the law of the package: the code conforms to it, or the document changes first.
This file is its short version. The package is being built by sub-spike 9c, the identity provider role
([beffroi-php/beffroi#645](https://github.com/beffroi-php/beffroi/issues/645)): it holds the identity provider of a
tenant so far, its signing key, kept by the KMS as every key of the tenant, the self-signed certificate around that
key and the metadata that publishes it, the next key's certificate beside the current one before it signs anything;
and the service providers of the tenant, declared in its configuration, their metadata read from a file or an `https`
URL, trusted by that channel or verified under pinned certificates, refused when expired or older than the document
accepted, and refused when they ask for encryption without a key for it; and the signature the authentication requests
of a service provider need, required unless its declaration says it does not sign and its metadata do not say it
does, whatever the tenant announces, the assertion going only to an assertion consumer service of its accepted
metadata; and single sign-on: a request received over HTTP-Redirect or HTTP-POST, answered from the session of the
core or after its login, with a response and an assertion both signed by the key of the tenant, valid five minutes,
addressed to that request, carrying a persistent `NameID` of its own per service provider and the attributes its
declaration maps from the claims the provider serves; and Single Logout started by a service provider: a signed
`LogoutRequest` received over either binding, accepted once, ending the sessions of the core it names when their user
is the principal of its `NameID`, as every session of the core ends, and answered with a signed `LogoutResponse` at a
single logout service of the accepted metadata of that service provider, each service provider's part in a session
being recorded for the logout the identity provider starts.

The package requires PHP 8.4 or later, `beffroi/core`, `beffroi/saml2-model`, `beffroi/saml2-bindings`,
`beffroi/xml-security` and `spomky-labs/pki-framework`.

## What its code never calls

Section 8 of the specification, enforced in `src/` and in `tests/` by the PHPStan rules of the monorepo
(`.ci-tools/phpstan-saml.neon`): `validateAuthenticatedByBinding()`, the binding's authentication being the word of
`saml2-bindings` alone; `Closure::bind()`, `Closure::bindTo()` and `Closure::call()`; Reflection; `unserialize()` and
`__unserialize()`. Each would let a message received by `saml2-bindings` be paired with a signature verified over
another input. A first-class callable, a callable string or a callable array naming one of them is refused as the
call is.

## Development

From the root of the monorepo, which holds the toolchain of every package:

```bash
composer install
castor prepare-pr                                # Mago lint and format, Rector, PHPStan, Deptrac
castor phpstan                                   # this package under .ci-tools/phpstan-saml.neon: level max, no baseline, the bans of section 8
castor phpstan-saml-rules                        # the bans of section 8 proven: one line of the fixture per banned form, compared to what PHPStan reports
castor deptrac                                   # the layers of section 2 and the graph of the packages
```

Every task runs inside the `ghcr.io/spomky-labs/phpqa` image when Docker is available.

## Security

See the [security policy](https://github.com/beffroi-php/beffroi/blob/0.0.x/SECURITY.md) of the monorepo: private reporting, an advisory and a CVE for
every fix.

## License

MIT, see the [LICENSE](https://github.com/beffroi-php/beffroi/blob/0.0.x/LICENSE) of the monorepo.
