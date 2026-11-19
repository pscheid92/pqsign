# Change-password command

* **Author:** Patrick Scheid
* **Date:** 2026-11-19

## Overview

A secret key's password is fixed today: it is set by `generate`, and the only way to change it is to generate a new key, which means a new fingerprint and new trust for everyone who verifies with it. This concept adds `pqsign change-password`, which re-encrypts an existing secret key file under a new password and the current Argon2id parameters. The key, its key ID, its fingerprint, its `.pub` file and every signature it made stay the same.

It works for both secret key formats. A format v1 file stays format v1 and a format v2 file stays format v2, because the command re-encrypts the decrypted payload bytes unchanged instead of re-encoding the key. That needs no format v1 encoder, which pqsign 0.4 removed.

## Analysis

### Re-encrypt the payload, don't re-encode the key

A secret key file is a 71-byte prefix (header 14, KDF parameters 17, salt 16, nonce 24), then the encrypted payload and its 16-byte tag. The header holds the magic, the format version, the file type and the key ID. It is not used as associated data, so it can be kept byte for byte while everything after the KDF block is replaced.

`decrypt_payload` in `src/format/secret_key.rs` already decrypts either format version into a wiped buffer without parsing it, and its comment names this use. The command:

1. reads and checks the file as `read_with` does today, including the per-version ciphertext length, before asking for any password;
2. decrypts the payload with the current password;
3. decodes the plaintext with the existing `decode_v1` or `decode_v2`, so the format v1 key-ID check and the format v2 derived-key-ID check run, and a file that would not load is never rewritten;
4. encrypts the same plaintext bytes with the new password, the current Argon2id parameters, and a fresh salt and nonce;
5. writes the unchanged header, the new KDF block, salt, nonce and ciphertext.

`decode_v1` stays frozen and remains the only format v1 code. The format v2 brief kept a format v1 encoder so that format v1 keys could get a new password later; the implementation dropped it, and this approach makes it unnecessary.

### Argon2id parameters

The file is written with `Kdf::argon2id()`, 256 MiB and 3 passes, the same as `generate`. The CLI offers no other values. A key written through the library with stronger parameters gets the defaults instead; that is accepted, because only library callers and tests choose parameters, and the status line names the parameters written. Using the same password again is allowed: it gives the file a fresh salt and nonce and moves a key with weaker parameters, such as one from a test, to the defaults.

### Write safety

The file being replaced is often the only copy of the key. Two things protect it:

- **Verify before replacing.** The new file bytes are decrypted and decoded in memory with the new password, through the same read path, before anything touches the disk. That costs one extra Argon2id run, about 0.4 s, and catches an encoding bug while the old file still exists.
- **Atomic replace.** `file::write` writes a temporary file in the same directory with mode 0600, fsyncs it, renames it over the key file, resolves a symlink to its target, and syncs the directory. A crash leaves either the old file or the new one.

No backup file is kept: a `.bak` protected by the old password defeats the point when that password leaked.

### What it cannot do

Changing the password protects the file from now on. It does not reach copies made earlier: backups, a synced copy, another hard link to the same file, or a file an attacker already has. If the password and the file leaked together, the key is compromised and needs replacing with `generate`. The docs and the command's help have to say this.

### Order of checks and output

1. Resolve the key path, with the same default as `sign` (`~/.pqsign/default.key`).
2. Warn when other users can write to the key's directory, and when a password file is accessible by other users, as `sign` and `generate` do. The key file's own permissions need no warning: the new file is written with mode 0600.
3. Check everything that needs no password: header, KDF block, ciphertext length.
4. Ask for the current password, decrypt and decode. A wrong current password fails here, before the user types a new one twice, and leaves the file byte for byte unchanged.
5. Ask for the new password.
6. Encode, verify, write.
7. Print the path, key ID, fingerprint and Argon2id parameters to stderr. Nothing goes to stdout.

### Command line

```
pqsign change-password [-s KEY] [--password-stdin | --password-file PATH] [--new-password-file PATH]
```

- The current password comes from the existing `PasswordArgs`: the terminal prompt, `--password-stdin` or `--password-file`.
- The new password comes from a prompt that asks twice, or from `--new-password-file`, read with `PasswordSource::read_new`, so the empty and length rules of `generate` apply.
- Standard input is only ever used for the current password, so the two can never be confused.
- No alias, such as `passwd`.

## Goals vs. Non-Goals

* **In-Scope Goals:**
  * `pqsign change-password` re-encrypts a secret key file under a new password and the current Argon2id parameters.
  * Format v1 and format v2 files keep their format version, header, key ID and fingerprint; the `.pub` file is not touched.
  * The new file is verified in memory before it atomically replaces the old one.
  * Usable without a terminal, through `--password-file` or `--password-stdin` and `--new-password-file`.
  * A library function, `format::secret_key::change_password`, that the command and the tests use.
* **Out-of-Scope Non-Goals:**
  * Converting format v1 keys to format v2. This is impossible, because an expanded ML-DSA key doesn't contain its seed.
  * Choosing Argon2id parameters on the command line.
  * Removing encryption; empty passwords stay rejected.
  * Changing the key ID, or rewriting the `.pub` file.
  * Revoking earlier copies of the file, or keeping a backup.
  * Authenticating the header as associated data.

## Alternatives Weighed

* **Support format v2 only.** Rejected by author: every key from pqsign 0.1 to 0.3, including the release key, would be stuck with its password.
* **Bring back a format v1 encoder.** Rejected by author: it adds code that would have to stay frozen next to `decode_v1`, for no gain over re-encrypting the decrypted bytes.
* **Keep the file's Argon2id parameters, or take the stronger of the file's and the defaults per parameter.** Rejected by author in favour of the defaults, the same as `generate`. The per-parameter maximum never weakens a key and is the fallback if that matters later.
* **Flags for the Argon2id parameters.** Rejected by author: new command-line surface that nobody has asked for.
* **A prompt-only new password.** Rejected by author: the command could not be scripted or tested end to end.
* **`--new-password-stdin`.** Rejected by author: it needs a rule for which password comes from standard input, and a wrong guess sets a password the user didn't mean.
* **Atomic replace without verifying first.** Rejected by author: an encoding bug would replace the only copy of a key with an unreadable file.

## Key Decisions & Staging for Next Steps

Decided during ideation:

1. The command changes the password and moves the file to the current Argon2id parameters. The key, key ID, fingerprint and `.pub` file never change.
2. Format v1 and v2 files are re-encrypted by keeping the header and the decrypted payload bytes. The plaintext is decoded first, so the key-ID checks run before anything is written.
3. Argon2id parameters are always `Kdf::argon2id()`.
4. The command is `pqsign change-password`, without an alias. The current password uses `PasswordArgs`; the new password comes from a confirmed prompt or `--new-password-file`; standard input carries the current password only.
5. The new bytes are verified in memory before an atomic replace. No backup file. The same password is allowed.
6. Checks that need no password run first, the current password is checked before the new one is asked for, and the output goes to stderr.

For the draft to settle:

1. **Library API:** where `change_password` lives, its signature, and how it shares the header, length and decrypt steps with `read_with` without duplicating them.
2. **Error wording** for a wrong current password, and whether it differs from `sign`'s.
3. **Documentation:** README usage, the limits under "What it cannot do", `docs/cryptography.md`, and the help text.
4. **Test plan:**
   - all three fixtures (`v1.key`, `v1-random-id.key`, `v2.key`) keep their version, length, header, key ID and fingerprint, load with the new password only, and sign
   - the old password fails afterwards
   - a wrong current password leaves the file byte for byte unchanged and never asks for a new one
   - new passwords that are empty, too long or don't match are rejected before writing
   - a scripted CLI run with `--password-file` and `--new-password-file`, and with `--password-stdin`
   - the rewritten file has mode 0600 and the Argon2id defaults
5. **Release:** a minor version, 0.5.0, since it adds a command and changes no format.
