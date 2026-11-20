## Verifying this release

Every archive has a `.pqsig` signature (and a `.v1.pqsig` for pqsign 0.1) from the release key, fingerprint `BLAKE2b-256:tgolgaKRfSGSvflaZqCjVtX+YXy6I+/tgvAbOW/npIc`, and a build provenance attestation:

```bash
pqsign verify pqsign-x86_64-unknown-linux-gnu.tar.gz -p release.key.pub
gh attestation verify pqsign-x86_64-unknown-linux-gnu.tar.gz --repo pscheid92/pqsign --signer-workflow pscheid92/pqsign/.github/workflows/release.yml
```

The binaries are reproducible: [rebuild one yourself](https://github.com/pscheid92/pqsign/blob/{{TAG}}/docs/install.md#rebuild-a-release-binary) and compare it with the binary in the archive.
