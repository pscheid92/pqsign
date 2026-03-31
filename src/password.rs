use std::io::stdin;

use zeroize::Zeroizing;

use crate::errors::Error;

pub fn prompt_new_password() -> Result<Zeroizing<String>, Error> {
    let password = read_password("Password: ")?;
    let confirm = read_password("Confirm password: ")?;
    validate_new_password(&password, &confirm)?;
    Ok(password)
}

pub fn validate_new_password(password: &str, confirm: &str) -> Result<(), Error> {
    if password.is_empty() {
        return Err(Error::PasswordEmpty);
    }

    if password != confirm {
        return Err(Error::PasswordMismatch);
    }

    Ok(())
}

pub fn read_password(prompt: &str) -> Result<Zeroizing<String>, Error> {
    let fallback = |_| {
        let mut line = String::new();
        stdin().read_line(&mut line)?;
        Ok(Zeroizing::new(line.trim_end().to_string()))
    };

    rpassword::prompt_password(prompt).map(Zeroizing::new).or_else(fallback)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_matching_passwords() {
        validate_new_password("secret", "secret").unwrap();
    }

    #[test]
    fn test_validate_empty_password() {
        let err = validate_new_password("", "").unwrap_err();
        assert!(matches!(err, Error::PasswordEmpty));
    }

    #[test]
    fn test_validate_mismatched_passwords() {
        let err = validate_new_password("foo", "bar").unwrap_err();
        assert!(matches!(err, Error::PasswordMismatch));
    }

    #[test]
    fn test_validate_empty_confirm_mismatches() {
        let err = validate_new_password("secret", "").unwrap_err();
        assert!(matches!(err, Error::PasswordMismatch));
    }
}
