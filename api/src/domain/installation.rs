//! Pure validation for installation registration and heartbeat input, and device
//! public-key identity. The client keeps its Ed25519 private key local (OS keyring);
//! only the public key is registered here, fingerprinted for stable lookup.

use base64::Engine;
use sha2::{Digest, Sha256};

/// Raw registration input as received from the client.
#[derive(Debug, Clone, Copy)]
pub struct RegistrationInput<'a> {
    pub install_key: &'a str,
    pub product_key: Option<&'a str>,
    pub app_version: Option<&'a str>,
    pub build_id: Option<&'a str>,
    pub platform: Option<&'a str>,
    pub architecture: Option<&'a str>,
    pub package_format: Option<&'a str>,
    pub updater_version: Option<&'a str>,
    pub device_public_key: Option<&'a str>,
    pub device_label: Option<&'a str>,
}

/// Registration input after validation/normalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedRegistration {
    pub install_key: String,
    pub product_key: String,
    pub app_version: Option<String>,
    pub build_id: Option<String>,
    pub platform: Option<String>,
    pub architecture: Option<String>,
    pub package_format: Option<String>,
    pub updater_version: Option<String>,
    pub device: Option<ValidatedDevice>,
}

/// A validated device public key: canonical base64 plus a SHA-256 hex fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedDevice {
    pub public_key: String,
    pub public_key_fpr: String,
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallationValidationError {
    pub field: &'static str,
    pub message: &'static str,
}

fn err(field: &'static str, message: &'static str) -> InstallationValidationError {
    InstallationValidationError { field, message }
}

/// Client-generated stable key making registration idempotent. Long enough to be
/// collision-resistant, restricted to URL/log-safe characters (UUIDs pass).
fn clean_install_key(value: &str) -> Result<String, InstallationValidationError> {
    let value = value.trim();
    if value.len() < 8 {
        return Err(err("install_key", "must be at least 8 characters"));
    }
    if value.len() > 120 {
        return Err(err("install_key", "must be at most 120 characters"));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
    {
        return Err(err(
            "install_key",
            "must contain only letters, numbers, '-', '_', '.', or ':'",
        ));
    }
    Ok(value.to_string())
}

fn clean_product_key(value: Option<&str>) -> Result<String, InstallationValidationError> {
    let value = match value.map(str::trim) {
        Some(v) if !v.is_empty() => v,
        _ => return Ok("authorforge".to_string()),
    };
    if value.len() > 120 || !value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(err(
            "product_key",
            "must contain only letters, numbers, and underscores",
        ));
    }
    Ok(value.to_string())
}

/// Optional version string ("1.4.0", "2.0.0-beta.1+build5").
pub fn clean_app_version(
    value: Option<&str>,
) -> Result<Option<String>, InstallationValidationError> {
    let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    if value.len() > 64 {
        return Err(err("app_version", "must be at most 64 characters"));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+'))
    {
        return Err(err(
            "app_version",
            "must contain only letters, numbers, '.', '-', '_', or '+'",
        ));
    }
    Ok(Some(value.to_string()))
}

fn clean_build_id(value: Option<&str>) -> Result<Option<String>, InstallationValidationError> {
    let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    if value.len() > 120 {
        return Err(err("build_id", "must be at most 120 characters"));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
    {
        return Err(err(
            "build_id",
            "must contain only letters, numbers, '.', '-', '_', or ':'",
        ));
    }
    Ok(Some(value.to_string()))
}

fn clean_platform(value: Option<&str>) -> Result<Option<String>, InstallationValidationError> {
    let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    if matches!(value, "windows" | "linux" | "darwin") {
        Ok(Some(value.to_string()))
    } else {
        Err(err("platform", "must be windows, linux, or darwin"))
    }
}

fn clean_architecture(value: Option<&str>) -> Result<Option<String>, InstallationValidationError> {
    let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    if matches!(value, "x86_64" | "aarch64" | "i686" | "armv7") {
        Ok(Some(value.to_string()))
    } else {
        Err(err(
            "architecture",
            "must be x86_64, aarch64, i686, or armv7",
        ))
    }
}

fn clean_package_format(
    value: Option<&str>,
) -> Result<Option<String>, InstallationValidationError> {
    let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    if value.len() > 40 {
        return Err(err("package_format", "must be at most 40 characters"));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        return Err(err(
            "package_format",
            "must contain only letters, numbers, '.', '-', or '_'",
        ));
    }
    Ok(Some(value.to_string()))
}

fn clean_device_label(value: Option<&str>) -> Result<Option<String>, InstallationValidationError> {
    let Some(value) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    if value.len() > 80 {
        return Err(err("device_label", "must be at most 80 characters"));
    }
    if value.chars().any(char::is_control) {
        return Err(err("device_label", "must not contain control characters"));
    }
    Ok(Some(value.to_string()))
}

/// Validate a base64 Ed25519 public key: it must decode (standard alphabet, padded) to
/// exactly 32 bytes. Returns the canonical re-encoding plus a SHA-256 hex fingerprint so
/// alternate encodings of the same key map to one device row.
fn clean_device_public_key(value: &str) -> Result<(String, String), InstallationValidationError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 64 {
        return Err(err(
            "device_public_key",
            "must be a base64-encoded 32-byte Ed25519 public key",
        ));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| {
            err(
                "device_public_key",
                "must be valid standard base64 with padding",
            )
        })?;
    if bytes.len() != 32 {
        return Err(err("device_public_key", "must decode to exactly 32 bytes"));
    }
    let canonical = base64::engine::general_purpose::STANDARD.encode(&bytes);
    let fingerprint = hex::encode(Sha256::digest(&bytes));
    Ok((canonical, fingerprint))
}

pub fn validate_registration(
    input: RegistrationInput<'_>,
) -> Result<ValidatedRegistration, InstallationValidationError> {
    let label = clean_device_label(input.device_label)?;
    let device = match input
        .device_public_key
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        Some(raw) => {
            let (public_key, public_key_fpr) = clean_device_public_key(raw)?;
            Some(ValidatedDevice {
                public_key,
                public_key_fpr,
                label,
            })
        }
        None if label.is_some() => {
            return Err(err(
                "device_label",
                "requires device_public_key to be provided",
            ));
        }
        None => None,
    };

    Ok(ValidatedRegistration {
        install_key: clean_install_key(input.install_key)?,
        product_key: clean_product_key(input.product_key)?,
        app_version: clean_app_version(input.app_version)?,
        build_id: clean_build_id(input.build_id)?,
        platform: clean_platform(input.platform)?,
        architecture: clean_architecture(input.architecture)?,
        package_format: clean_package_format(input.package_format)?,
        updater_version: clean_app_version(input.updater_version)?,
        device,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_b64(byte: u8) -> String {
        base64::engine::general_purpose::STANDARD.encode([byte; 32])
    }

    #[test]
    fn accepts_full_registration_and_normalizes() {
        let key = key_b64(7);
        let v = validate_registration(RegistrationInput {
            install_key: "  9f1c2d3e-4b5a-6789-0abc-def012345678 ",
            product_key: None,
            app_version: Some(" 1.4.0-beta.1 "),
            build_id: Some(" 20260611.abc123 "),
            platform: Some("linux"),
            architecture: Some("x86_64"),
            package_format: Some("appimage"),
            updater_version: Some("2.0.0"),
            device_public_key: Some(&key),
            device_label: Some("  Work laptop "),
        })
        .expect("valid registration");

        assert_eq!(v.install_key, "9f1c2d3e-4b5a-6789-0abc-def012345678");
        assert_eq!(v.product_key, "authorforge");
        assert_eq!(v.app_version.as_deref(), Some("1.4.0-beta.1"));
        assert_eq!(v.build_id.as_deref(), Some("20260611.abc123"));
        assert_eq!(v.platform.as_deref(), Some("linux"));
        assert_eq!(v.architecture.as_deref(), Some("x86_64"));
        assert_eq!(v.package_format.as_deref(), Some("appimage"));
        assert_eq!(v.updater_version.as_deref(), Some("2.0.0"));
        let device = v.device.expect("device present");
        assert_eq!(device.public_key, key);
        assert_eq!(device.public_key_fpr.len(), 64); // sha256 hex
        assert_eq!(device.label.as_deref(), Some("Work laptop"));
    }

    #[test]
    fn rejects_short_or_malformed_install_key() {
        for bad in ["", "short", "has spaces here", "bad/slash-key"] {
            let e = validate_registration(RegistrationInput {
                install_key: bad,
                product_key: None,
                app_version: None,
                build_id: None,
                platform: None,
                architecture: None,
                package_format: None,
                updater_version: None,
                device_public_key: None,
                device_label: None,
            })
            .expect_err("invalid install key");
            assert_eq!(e.field, "install_key");
        }
    }

    #[test]
    fn rejects_bad_public_key_material() {
        // Not base64 / wrong length both fail.
        for bad in ["not-base64!!!", "QUJD"] {
            let e = validate_registration(RegistrationInput {
                install_key: "valid-install-key",
                product_key: None,
                app_version: None,
                build_id: None,
                platform: None,
                architecture: None,
                package_format: None,
                updater_version: None,
                device_public_key: Some(bad),
                device_label: None,
            })
            .expect_err("invalid key");
            assert_eq!(e.field, "device_public_key");
        }
    }

    #[test]
    fn fingerprint_is_stable_for_same_key_bytes() {
        let a = clean_device_public_key(&key_b64(9)).expect("valid");
        let b = clean_device_public_key(&key_b64(9)).expect("valid");
        let c = clean_device_public_key(&key_b64(10)).expect("valid");
        assert_eq!(a.1, b.1);
        assert_ne!(a.1, c.1);
    }

    #[test]
    fn label_without_public_key_is_rejected() {
        let e = validate_registration(RegistrationInput {
            install_key: "valid-install-key",
            product_key: None,
            app_version: None,
            build_id: None,
            platform: None,
            architecture: None,
            package_format: None,
            updater_version: None,
            device_public_key: None,
            device_label: Some("Laptop"),
        })
        .expect_err("label without key");
        assert_eq!(e.field, "device_label");
    }

    #[test]
    fn rejects_malformed_app_version() {
        let e = clean_app_version(Some("1.0 beta")).expect_err("space");
        assert_eq!(e.field, "app_version");
        assert_eq!(clean_app_version(Some("  ")).expect("blank is none"), None);
        assert_eq!(
            clean_app_version(Some("2.0.0+build.5"))
                .expect("valid")
                .as_deref(),
            Some("2.0.0+build.5")
        );
    }

    #[test]
    fn update_metadata_is_bounded_and_enumerated() {
        assert_eq!(
            clean_build_id(Some(" 20260611:abc ")).unwrap().as_deref(),
            Some("20260611:abc")
        );
        assert!(clean_build_id(Some("bad/build")).is_err());
        assert_eq!(
            clean_platform(Some("linux")).unwrap().as_deref(),
            Some("linux")
        );
        assert!(clean_platform(Some("freebsd")).is_err());
        assert_eq!(
            clean_architecture(Some("x86_64")).unwrap().as_deref(),
            Some("x86_64")
        );
        assert!(clean_architecture(Some("amd64")).is_err());
        assert_eq!(
            clean_package_format(Some("appimage")).unwrap().as_deref(),
            Some("appimage")
        );
        assert!(clean_package_format(Some("bad format")).is_err());
    }
}
