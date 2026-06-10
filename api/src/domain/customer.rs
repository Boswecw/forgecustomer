//! Customer profile validation and status helpers.

/// Raw profile fields accepted during API-owned account provisioning.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProvisionProfileInput<'a> {
    pub display_name: Option<&'a str>,
    pub country_code: Option<&'a str>,
    pub timezone: Option<&'a str>,
}

/// Sanitized profile fields safe to persist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedProvisionProfile {
    pub display_name: Option<String>,
    pub country_code: Option<String>,
    pub timezone: Option<String>,
}

/// Field-level validation error for account provisioning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvisionProfileValidationError {
    pub field: &'static str,
    pub message: &'static str,
}

fn trimmed_optional(value: Option<&str>, max_len: usize) -> Option<String> {
    value.map(str::trim).filter(|v| !v.is_empty()).map(|v| {
        if v.len() > max_len {
            v[..max_len].to_string()
        } else {
            v.to_string()
        }
    })
}

fn validate_country_code(
    value: Option<&str>,
) -> Result<Option<String>, ProvisionProfileValidationError> {
    let Some(raw) = value.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let code = raw.to_ascii_uppercase();
    if code.len() == 2 && code.chars().all(|c| c.is_ascii_uppercase()) {
        Ok(Some(code))
    } else {
        Err(ProvisionProfileValidationError {
            field: "country_code",
            message: "country_code must be a two-letter ISO country code",
        })
    }
}

/// Validate customer-controlled profile decoration. Commercial state, customer type, and
/// status are never accepted from clients.
pub fn validate_provision_profile(
    input: ProvisionProfileInput<'_>,
) -> Result<ValidatedProvisionProfile, ProvisionProfileValidationError> {
    let display_name = trimmed_optional(input.display_name, 120);
    let country_code = validate_country_code(input.country_code)?;
    let timezone = trimmed_optional(input.timezone, 80);

    Ok(ValidatedProvisionProfile {
        display_name,
        country_code,
        timezone,
    })
}

/// Normalize an email claim from the trusted Supabase JWT. Malformed or empty values are
/// ignored; Supabase Auth remains the source of truth for login identity and verification.
pub fn normalize_email_claim(value: Option<&str>) -> Option<String> {
    let email = value?.trim().to_ascii_lowercase();
    if email.contains('@') && email.len() <= 320 {
        Some(email)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provision_profile_trims_optional_fields() {
        let validated = validate_provision_profile(ProvisionProfileInput {
            display_name: Some("  Ada Lovelace  "),
            country_code: Some("us"),
            timezone: Some("  America/Kentucky/Louisville "),
        })
        .expect("valid profile");

        assert_eq!(validated.display_name.as_deref(), Some("Ada Lovelace"));
        assert_eq!(validated.country_code.as_deref(), Some("US"));
        assert_eq!(
            validated.timezone.as_deref(),
            Some("America/Kentucky/Louisville")
        );
    }

    #[test]
    fn provision_profile_rejects_invalid_country_code() {
        let err = validate_provision_profile(ProvisionProfileInput {
            country_code: Some("USA"),
            ..Default::default()
        })
        .expect_err("invalid country");

        assert_eq!(err.field, "country_code");
    }

    #[test]
    fn empty_strings_become_none() {
        let validated = validate_provision_profile(ProvisionProfileInput {
            display_name: Some("   "),
            country_code: Some(""),
            timezone: Some(" "),
        })
        .expect("empty strings are optional");

        assert_eq!(validated.display_name, None);
        assert_eq!(validated.country_code, None);
        assert_eq!(validated.timezone, None);
    }

    #[test]
    fn email_claim_is_normalized() {
        assert_eq!(
            normalize_email_claim(Some(" USER@Example.COM ")).as_deref(),
            Some("user@example.com")
        );
        assert_eq!(normalize_email_claim(Some("not-an-email")), None);
        assert_eq!(normalize_email_claim(None), None);
    }
}
