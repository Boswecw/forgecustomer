//! Checkout request validation. Customer input here selects a catalog plan and browser
//! redirect targets only; Stripe price ids and commercial state remain server-owned.

#[derive(Debug, Clone, Copy)]
pub struct CheckoutInput<'a> {
    pub product_key: Option<&'a str>,
    pub plan_key: &'a str,
    pub success_url: &'a str,
    pub cancel_url: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedCheckoutInput {
    pub product_key: String,
    pub plan_key: String,
    pub success_url: String,
    pub cancel_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutValidationError {
    pub field: &'static str,
    pub message: &'static str,
}

fn clean_key(value: &str, field: &'static str) -> Result<String, CheckoutValidationError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(CheckoutValidationError {
            field,
            message: "field is required",
        });
    }
    if value.len() > 120 || !value.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(CheckoutValidationError {
            field,
            message: "field must contain only letters, numbers, and underscores",
        });
    }
    Ok(value.to_string())
}

fn clean_checkout_url(value: &str, field: &'static str) -> Result<String, CheckoutValidationError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(CheckoutValidationError {
            field,
            message: "field is required",
        });
    }
    if value.len() > 2048 || !(value.starts_with("https://") || value.starts_with("http://")) {
        return Err(CheckoutValidationError {
            field,
            message: "field must be an http or https URL",
        });
    }
    Ok(value.to_string())
}

pub fn validate_checkout_input(
    input: CheckoutInput<'_>,
) -> Result<ValidatedCheckoutInput, CheckoutValidationError> {
    Ok(ValidatedCheckoutInput {
        product_key: match input.product_key {
            Some(value) if !value.trim().is_empty() => clean_key(value, "product_key")?,
            _ => "authorforge".to_string(),
        },
        plan_key: clean_key(input.plan_key, "plan_key")?,
        success_url: clean_checkout_url(input.success_url, "success_url")?,
        cancel_url: clean_checkout_url(input.cancel_url, "cancel_url")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_product_key_and_trims_fields() {
        let validated = validate_checkout_input(CheckoutInput {
            product_key: None,
            plan_key: " authorforge_pro ",
            success_url: " https://example.com/success ",
            cancel_url: "https://example.com/cancel",
        })
        .expect("valid checkout input");

        assert_eq!(validated.product_key, "authorforge");
        assert_eq!(validated.plan_key, "authorforge_pro");
        assert_eq!(validated.success_url, "https://example.com/success");
    }

    #[test]
    fn rejects_non_http_redirect_url() {
        let err = validate_checkout_input(CheckoutInput {
            product_key: None,
            plan_key: "authorforge_pro",
            success_url: "authorforge://checkout",
            cancel_url: "https://example.com/cancel",
        })
        .expect_err("invalid url");

        assert_eq!(err.field, "success_url");
    }

    #[test]
    fn rejects_blank_plan_key() {
        let err = validate_checkout_input(CheckoutInput {
            product_key: None,
            plan_key: " ",
            success_url: "https://example.com/success",
            cancel_url: "https://example.com/cancel",
        })
        .expect_err("blank plan");

        assert_eq!(err.field, "plan_key");
    }
}
