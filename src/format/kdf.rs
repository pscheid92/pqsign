use crate::errors::Error;

const KDF_ARGON2ID_BYTE: u8 = 0x02;
const DEFAULT_MEM_LIMIT: u64 = 256 * MIB;
const DEFAULT_OPS_LIMIT: u64 = 3;

/// Upper limits for parameters read from key files, so a corrupt or tampered file cannot tie pqsign up for
/// hours or exhaust memory. They cover the strongest preset in docs/kdf-comparison.md, libsodium's SENSITIVE
/// (1 GiB, 4 iterations), and keep a derivation under about ten seconds. Raising them later stays compatible
/// with existing key files; lowering them would not. The lower limits are Argon2id's own.
const MAX_MEM_LIMIT: u64 = 1024 * MIB;
const MAX_OPS_LIMIT: u64 = 16;

const MIB: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kdf {
    Argon2id { mem_limit: u64, ops_limit: u64 },
}

impl Kdf {
    pub fn argon2id() -> Self {
        Kdf::Argon2id {
            mem_limit: DEFAULT_MEM_LIMIT,
            ops_limit: DEFAULT_OPS_LIMIT,
        }
    }

    pub fn mem_limit(&self) -> u64 {
        match self {
            Kdf::Argon2id { mem_limit, .. } => *mem_limit,
        }
    }

    pub fn ops_limit(&self) -> u64 {
        match self {
            Kdf::Argon2id { ops_limit, .. } => *ops_limit,
        }
    }

    /// Checks parameters before any work is done with them: those read from a key file, and those a key is
    /// about to be written with.
    pub(super) fn check(&self) -> Result<(), Error> {
        let Kdf::Argon2id { mem_limit, ops_limit } = *self;

        if mem_limit > MAX_MEM_LIMIT {
            let msg = format!(
                "secret key file asks for {} of Argon2id memory; pqsign accepts at most {}",
                exact_size(mem_limit),
                exact_size(MAX_MEM_LIMIT)
            );
            let err = Error::InvalidFormat(msg);
            return Err(err);
        }

        if ops_limit > MAX_OPS_LIMIT {
            let msg = format!("secret key file asks for {ops_limit} Argon2id iterations; pqsign accepts at most {MAX_OPS_LIMIT}");
            let err = Error::InvalidFormat(msg);
            return Err(err);
        }

        if !mem_limit.is_multiple_of(1024) {
            let msg = format!("secret key file has an Argon2id memory size of {mem_limit} bytes, which is not a whole number of KiB");
            let err = Error::InvalidFormat(msg);
            return Err(err);
        }

        super::crypto::argon2_params(mem_limit, ops_limit)
            .map(|_| ())
            .map_err(|reason| Error::InvalidFormat(format!("secret key file has invalid Argon2id parameters: {reason}")))
    }
}

/// In MiB when whole, else in KiB or bytes, so a value just over a limit is not rounded down onto it.
pub(super) fn exact_size(bytes: u64) -> String {
    if bytes.is_multiple_of(MIB) {
        format!("{} MiB", bytes / MIB)
    } else if bytes.is_multiple_of(1024) {
        format!("{} KiB", bytes / 1024)
    } else {
        format!("{bytes} bytes")
    }
}

pub(super) fn read_from(r: &mut impl std::io::Read) -> Result<Kdf, Error> {
    let kdf_byte = super::read_u8(r)?;
    let mem_limit = super::read_u64_le(r)?;
    let ops_limit = super::read_u64_le(r)?;

    let kdf = match kdf_byte {
        KDF_ARGON2ID_BYTE => Kdf::Argon2id { mem_limit, ops_limit },
        other => return Err(Error::InvalidFormat(format!("unknown KDF algorithm: 0x{other:02x}"))),
    };
    kdf.check()?;
    Ok(kdf)
}

pub(super) fn write_to(kdf: &Kdf, w: &mut impl std::io::Write) -> Result<(), Error> {
    let Kdf::Argon2id { mem_limit, ops_limit } = kdf;

    super::write_u8(w, KDF_ARGON2ID_BYTE)?;
    super::write_u64_le(w, *mem_limit)?;
    super::write_u64_le(w, *ops_limit)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(mem_limit: u64, ops_limit: u64) -> Result<Kdf, Error> {
        let data = [&[KDF_ARGON2ID_BYTE][..], &mem_limit.to_le_bytes(), &ops_limit.to_le_bytes()].concat();
        read_from(&mut data.as_slice())
    }

    fn rejection(mem_limit: u64, ops_limit: u64) -> String {
        match read(mem_limit, ops_limit) {
            Err(Error::InvalidFormat(msg)) => msg,
            Err(other) => panic!("expected InvalidFormat, got: {other}"),
            Ok(kdf) => panic!("expected an error, got {kdf:?}"),
        }
    }

    #[test]
    fn test_default_parameters_are_accepted() {
        let kdf = Kdf::argon2id();
        read(kdf.mem_limit(), kdf.ops_limit()).unwrap();
    }

    #[test]
    fn test_limits_are_inclusive() {
        read(MAX_MEM_LIMIT, MAX_OPS_LIMIT).unwrap();
        read(8 * 1024, 1).unwrap();
    }

    #[test]
    fn test_rejects_too_much_memory() {
        let msg = rejection(MAX_MEM_LIMIT + 1024, 3);
        assert!(
            msg.contains("asks for 1048577 KiB of Argon2id memory; pqsign accepts at most 1024 MiB"),
            "got: {msg}"
        );

        // Used to be truncated to 256 MiB by a cast and accepted.
        let msg = rejection((1 << 42) + 256 * MIB, 3);
        assert!(msg.contains("asks for 4194560 MiB"), "got: {msg}");
        let msg = rejection(u64::MAX, 3);
        assert!(msg.contains("asks for 18446744073709551615 bytes"), "got: {msg}");
    }

    #[test]
    fn test_rejects_too_many_iterations() {
        for ops in [MAX_OPS_LIMIT + 1, 1_000_000, (1 << 32) + 3, u64::MAX] {
            let msg = rejection(DEFAULT_MEM_LIMIT, ops);
            assert!(
                msg.contains(&format!("asks for {ops} Argon2id iterations; pqsign accepts at most 16")),
                "got: {msg}"
            );
        }
    }

    #[test]
    fn test_rejects_memory_that_is_not_whole_kib() {
        let msg = rejection(DEFAULT_MEM_LIMIT + 1, 3);
        assert!(msg.contains("268435457 bytes, which is not a whole number of KiB"), "got: {msg}");
    }

    #[test]
    fn test_rejects_parameters_argon2id_rejects() {
        for (mem, ops) in [(0, 3), (7 * 1024, 3), (DEFAULT_MEM_LIMIT, 0)] {
            let msg = rejection(mem, ops);
            assert!(msg.contains("invalid Argon2id parameters"), "got: {msg}");
        }
    }
}
