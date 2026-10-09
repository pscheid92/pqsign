# Security Policy

pqsign signs files with Ed25519 and ML-DSA-65 together, and its value depends on that code being correct. Reports of weaknesses are very welcome.

## Supported versions

Only the latest release receives security fixes. A fix ships as a new release; older versions are not patched. pqsign is still before 1.0, so a fix may include a breaking change when that is the safer option.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub: on the repository's **Security** tab, choose **Report a vulnerability**, or go directly to [the reporting form](https://github.com/pscheid92/pqsign/security/advisories/new). Please do not open a public issue for a vulnerability.

Useful details are:

- the pqsign version (`pqsign version`) and platform
- what an attacker can achieve, and under which assumptions
- the steps or files that reproduce it
- a proposed fix, if you have one

pqsign has a single maintainer, so there are no guaranteed response times; reports are handled as time allows. You are credited in the advisory and the release notes unless you prefer not to be.

## Disclosure

Details are made public once a fix is released, and the timing is agreed with the reporter.

## Scope

In scope:

- the pqsign command-line tool and library in this repository
- the key and signature file formats
- the release pipeline and the release signing key

Weaknesses in a dependency, such as `ed25519-dalek` or `fips204`, belong with that project. Please also report them here when pqsign is affected, so a fixed release can follow quickly. [docs/cryptography.md](docs/cryptography.md#implementation-status) lists the cryptographic dependencies and their review status.

## Release signing key

Releases are signed with the key in [`release.key.pub`](release.key.pub). Its fingerprint is:

```
BLAKE2b-256:tgolgaKRfSGSvflaZqCjVtX+YXy6I+/tgvAbOW/npIc
```

If the key were ever compromised, a security advisory would announce it, name the affected releases, and publish a new key with its fingerprint here and in the README.
