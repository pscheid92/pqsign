//! Reading and writing pqsign files.
//!
//! Reads are bounded: pqsign files are a few kilobytes, so anything much larger is rejected
//! without loading it. Writes are atomic: data goes to a temporary file in the destination
//! directory, which is synced and then renamed over the destination. A crash or failure at any
//! point leaves either the old file or the new one, never a partial write.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use tempfile::NamedTempFile;

use crate::errors::{Error, IoContext};

/// Upper bound for any file pqsign reads as one of its own.
///
/// The largest current file, a signature with a maximal trusted comment, is 4,415 bytes. The headroom
/// lets files from newer format versions reach their "requires a newer version" check.
pub(super) const MAX_FILE_LEN: u64 = 64 * 1024;

/// Reads a pqsign file, rejecting anything larger than [`MAX_FILE_LEN`] without loading it.
pub(super) fn read(path: &Path) -> Result<Vec<u8>, Error> {
    let file = fs::File::open(path).io_context(path)?;
    read_limited(file, MAX_FILE_LEN).io_context(path)?.ok_or_else(too_large)
}

/// Reads at most `limit` bytes, or returns `None` if there are more. Never reads past `limit + 1`
/// bytes, so endless inputs such as `/dev/zero` stop early.
fn read_limited(reader: impl Read, limit: u64) -> io::Result<Option<Vec<u8>>> {
    let mut data = Vec::new();
    reader.take(limit + 1).read_to_end(&mut data)?;
    Ok((data.len() as u64 <= limit).then_some(data))
}

fn too_large() -> Error {
    let msg = format!("not a pqsign file (larger than {} KiB)", MAX_FILE_LEN / 1024);
    Error::InvalidFormat(msg)
}

/// Who may read a file pqsign writes.
#[derive(Clone, Copy)]
pub(super) enum Access {
    /// The owner only: mode 0600 on Unix, whatever the umask.
    Private,
    /// Everyone the umask allows: mode 0644 with the usual umask, like any newly created file.
    Public,
}

/// A fully written and synced temporary file, waiting to be renamed into place.
pub(super) struct Staged {
    temp: NamedTempFile,
    dest: PathBuf,
}

impl Staged {
    pub(super) fn new(dest: &Path, data: &[u8], access: Access) -> Result<Self, Error> {
        let dest = resolve_symlink(dest);
        let dir = parent_dir(&dest);
        create_dir_all(dir).io_context(dir)?;

        let mut temp = temp_file_in(dir, &dest, access).io_context(&dest)?;
        temp.write_all(data).io_context(&dest)?;
        temp.as_file().sync_all().io_context(&dest)?;

        Ok(Staged { temp, dest })
    }

    /// Renames the file into place and returns its final path.
    ///
    /// Without `overwrite` an existing destination is never replaced, even one created after the caller checked.
    pub(super) fn commit(self, overwrite: bool) -> Result<PathBuf, Error> {
        let Staged { temp, dest } = self;
        let result = if overwrite { temp.persist(&dest) } else { temp.persist_noclobber(&dest) };

        match result {
            Ok(_) => Ok(dest),
            Err(err) if err.error.kind() == io::ErrorKind::AlreadyExists => Err(Error::FileExists(dest)),
            Err(err) => Err(err.error).io_context(&dest),
        }
    }
}

/// Writes `data` to `dest` atomically, replacing an existing file.
pub(super) fn write(dest: &Path, data: &[u8], access: Access) -> Result<(), Error> {
    let dest = Staged::new(dest, data, access)?.commit(true)?;
    sync_parent_dir(&dest);
    Ok(())
}

/// Makes completed renames durable by syncing the directory that holds `path`.
///
/// Best effort: the rename already happened, and some file systems do not support syncing directories.
pub(super) fn sync_parent_dir(path: &Path) {
    #[cfg(unix)]
    if let Ok(dir) = fs::File::open(parent_dir(path)) {
        let _ = dir.sync_all();
    }
    #[cfg(not(unix))]
    let _ = path;
}

/// Writes go to the file a symlink points to, so a symlinked key keeps working after an overwrite.
fn resolve_symlink(path: &Path) -> PathBuf {
    let is_symlink = fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink());
    match is_symlink {
        true => fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()),
        false => path.to_path_buf(),
    }
}

fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

/// Creates missing directories, accessible by the owner only on Unix. Existing directories are left alone.
fn create_dir_all(dir: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// A temporary file next to `dest`, named after it so a file left behind by a killed process is recognizable.
fn temp_file_in(dir: &Path, dest: &Path, access: Access) -> io::Result<NamedTempFile> {
    let name = dest.file_name().unwrap_or(dest.as_os_str()).to_string_lossy();
    let prefix = format!(".{name}.");

    let mut builder = tempfile::Builder::new();
    builder.prefix(&prefix).suffix(".tmp");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = match access {
            Access::Private => 0o600,
            Access::Public => 0o666,
        };
        builder.permissions(fs::Permissions::from_mode(mode));
    }
    #[cfg(not(unix))]
    let _ = access;
    builder.tempfile_in(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_limited_accepts_up_to_the_limit() {
        assert_eq!(read_limited(&[1u8; 8][..], 8).unwrap(), Some(vec![1u8; 8]));
        assert_eq!(read_limited(&[1u8; 9][..], 8).unwrap(), None);
        assert_eq!(read_limited(&[][..], 8).unwrap(), Some(vec![]));
    }

    #[test]
    fn test_read_limited_stops_on_endless_input() {
        assert_eq!(read_limited(io::repeat(0), MAX_FILE_LEN).unwrap(), None);
    }

    #[test]
    fn test_read_rejects_files_over_the_limit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("file");

        fs::write(&path, vec![0u8; MAX_FILE_LEN as usize]).unwrap();
        assert_eq!(read(&path).unwrap().len(), MAX_FILE_LEN as usize);

        fs::write(&path, vec![0u8; MAX_FILE_LEN as usize + 1]).unwrap();
        match read(&path) {
            Err(Error::InvalidFormat(msg)) => assert!(msg.contains("larger than 64 KiB"), "got: {msg}"),
            Err(other) => panic!("expected InvalidFormat, got: {other}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }
}
