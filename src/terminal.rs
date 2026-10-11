//! Printing text that may come from someone else.
//!
//! File names and paths can come from an archive or a download. Printed raw, a control character in one can
//! recolor or erase terminal output, and a line break can add a line that looks like pqsign's own. Everything
//! pqsign prints that it did not write itself goes through [`SafePath`] or [`SafeText`], or is rejected before
//! it gets there, as trusted comments are.

use std::fmt::{self, Write as _};
use std::path::Path;

/// Whether `c` must not reach the terminal as is. Control characters other than tab can move the cursor,
/// erase or recolor terminal output. Bidirectional overrides and isolates reorder how text is displayed, so
/// `invoice\u{202e}fdp.exe` reads as `invoiceexe.pdf`.
///
/// Trusted comments follow the same rule, so a valid comment prints unchanged.
pub fn is_unsafe(c: char) -> bool {
    (c.is_control() && c != '\t') || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

/// Displays a path with unsafe characters written as Rust-style escapes such as `\u{1b}`, and bytes that are not
/// valid UTF-8 as `\xNN`. Backslashes stay as they are, so Windows paths read as usual.
pub struct SafePath<'a>(pub &'a Path);

impl fmt::Display for SafePath<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for chunk in self.0.as_os_str().as_encoded_bytes().utf8_chunks() {
            write_escaped(f, chunk.valid())?;
            for byte in chunk.invalid() {
                write!(f, "\\x{byte:02x}")?;
            }
        }
        Ok(())
    }
}

/// Displays text with unsafe characters escaped like [`SafePath`] does.
pub struct SafeText<'a>(pub &'a str);

impl fmt::Display for SafeText<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_escaped(f, self.0)
    }
}

fn write_escaped(f: &mut fmt::Formatter<'_>, text: &str) -> fmt::Result {
    for c in text.chars() {
        if is_unsafe(c) {
            write!(f, "{}", c.escape_default())?;
        } else {
            f.write_char(c)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(text: &str) -> String {
        SafePath(Path::new(text)).to_string()
    }

    #[test]
    fn test_ordinary_paths_are_unchanged() {
        assert_eq!(path("dir/file.txt"), "dir/file.txt");
        assert_eq!(path("Bericht für März.pdf"), "Bericht für März.pdf");
        assert_eq!(path(r"C:\Users\me\file.txt"), r"C:\Users\me\file.txt");
        assert_eq!(path("a\tb"), "a\tb");
    }

    #[test]
    fn test_unsafe_characters_are_escaped() {
        assert_eq!(path("evil\x1b[32mGREEN\x1b[0m.txt"), "evil\\u{1b}[32mGREEN\\u{1b}[0m.txt");
        assert_eq!(path("a\nSignature: OK"), "a\\nSignature: OK");
        assert_eq!(path("a\rb\x7fc\u{9b}d"), "a\\rb\\u{7f}c\\u{9b}d");
        assert_eq!(path("invoice\u{202e}fdp.exe"), "invoice\\u{202e}fdp.exe");
        assert_eq!(path("x\u{2066}y"), "x\\u{2066}y");
    }

    #[test]
    fn test_escaping_twice_changes_nothing() {
        let once = path("evil\x1b[0m\n.txt");
        assert_eq!(SafeText(&once).to_string(), once);
    }

    #[cfg(unix)]
    #[test]
    fn test_bytes_that_are_not_utf8_stay_distinct() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let path = |bytes: &[u8]| SafePath(Path::new(OsStr::from_bytes(bytes))).to_string();
        assert_eq!(path(b"caf\xe9.txt"), "caf\\xe9.txt");
        assert_ne!(path(b"caf\xe9.txt"), path(b"caf\xe8.txt"));
    }

    #[test]
    fn test_text_is_escaped() {
        assert_eq!(SafeText("error: \x1b]0;title\x07").to_string(), "error: \\u{1b}]0;title\\u{7}");
    }
}
