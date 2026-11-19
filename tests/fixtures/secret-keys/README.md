# Secret key fixtures

These are test-only keys. Their password, `fixture-password`, is published here, so they must never sign anything real.

Each fixture was written once by the pqsign version named below and is never regenerated. `tests/fixtures.rs` checks that every later pqsign still loads them, signs with them and gets the pinned key ID and fingerprint. A new secret key format version adds new fixtures next to these.

| Fixture | Written by | Secret key format | Key ID | Fingerprint | Argon2id |
|---|---|---|---|---|---|
| `v1.key`, `v1.key.pub` | pqsign 0.3.1 | v1 | `EF0338D2AB2146C6` (fingerprint prefix) | `BLAKE2b-256:7wM40qshRsa+M1qXLcRWaXc1mvYu6PDv6Kf6UhQDFYE` | 64 KiB, 1 pass |
| `v1-random-id.key`, `v1-random-id.key.pub` | pqsign 0.1.1 | v1 | `0757CD16490BE8FF` (random) | `BLAKE2b-256:bOzpMPaanVm/F1w77nNsBz8a/ZBdmt+p+AN3m4QbZrw` | 256 MiB, 3 passes |
| `v2.key`, `v2.key.pub` | pqsign 0.4, when the format was introduced | v2 | `005D87F817789998` (fingerprint prefix) | `BLAKE2b-256:AF2H+Bd4mZjatXH099oBMQFnU4+6QwLGi5XVul4ekm0` | 64 KiB, 1 pass |

pqsign 0.1.1 writes the same files as 0.1.0, the first release, so `v1-random-id.key` stands for both. 0.1.1 can't choose the Argon2id parameters, so this fixture uses the defaults and takes about 0.4 s to load.

## How they were made

Each fixture comes from a small program outside the repository. The format v1 fixtures depend on the published crate, so each file is written by that release's own code rather than by the current tree. The format v2 fixture depends on the checkout that introduced the format.

`v1.key`, with `pqsign = "=0.3.1"` and `zeroize = "1"`:

```rust
use std::path::PathBuf;

use pqsign::domain::KeyPair;
use pqsign::format::{self, Kdf};
use zeroize::Zeroizing;

fn main() {
    let dir = PathBuf::from(std::env::args().nth(1).expect("usage: fixture-gen <dir>"));
    let (secret_key, public_key) = KeyPair::new().into_parts();
    let kdf = Kdf::Argon2id { mem_limit: 64 * 1024, ops_limit: 1 };
    format::write_secret_key(&dir.join("v1.key"), &secret_key, Zeroizing::new("fixture-password".to_string()), &kdf).unwrap();
    format::write_public_key(&dir.join("v1.key.pub"), &public_key).unwrap();
    println!("key ID {}  fingerprint {}", public_key.key_id(), public_key.fingerprint());
}
```

`v1-random-id.key`, with `pqsign = "=0.1.1"` and `zeroize = "1"`. In 0.1.1, `write_secret_key` takes no KDF parameter and `KeyPair::new` gives each key a random key ID:

```rust
use std::path::PathBuf;

use pqsign::domain::KeyPair;
use pqsign::format;
use zeroize::Zeroizing;

fn main() {
    let dir = PathBuf::from(std::env::args().nth(1).expect("usage: fixture-gen <dir>"));
    let (secret_key, public_key) = KeyPair::new().into_parts();
    format::write_secret_key(&dir.join("v1-random-id.key"), &secret_key, Zeroizing::new("fixture-password".to_string())).unwrap();
    format::write_public_key(&dir.join("v1-random-id.key.pub"), &public_key).unwrap();
    println!("key ID {}", public_key.key_id());
}
```

`v2.key`, with `pqsign = { path = "…" }` pointing at the checkout that introduced secret key format v2, and `zeroize = "1"`. A format v2 file is 151 bytes:

```rust
use std::path::PathBuf;

use pqsign::domain::SecretSeeds;
use pqsign::format::{self, Kdf};
use zeroize::Zeroizing;

fn main() {
    let dir = PathBuf::from(std::env::args().nth(1).expect("usage: fixture-gen <dir>"));
    let seeds = SecretSeeds::generate();
    let kdf = Kdf::Argon2id { mem_limit: 64 * 1024, ops_limit: 1 };
    let password = Zeroizing::new("fixture-password".to_string());
    let public_key = format::write_key_pair(&dir.join("v2.key"), &dir.join("v2.key.pub"), &seeds, password, false, &kdf).unwrap();
    println!("key ID {}  fingerprint {}", public_key.key_id(), public_key.fingerprint());
}
```
