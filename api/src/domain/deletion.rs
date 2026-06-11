//! The account-deletion state machine (pure rules; persistence in
//! `repositories::privacy`).
//!
//! ```text
//! requested -> verified -> cooling_off -> processing -> completed
//! ```
//! Terminal alternatives: `rejected` (operator) and `canceled` (customer). Cooling-off
//! is non-destructive so a customer cancel is always clean; commercial state is frozen
//! and anonymized only at execution.

/// The operator-driven forward transition from a given state, if any. `processing`
/// advances only through execution (anonymization), never through `advance`.
pub fn next_state(current: &str) -> Option<&'static str> {
    match current {
        "requested" => Some("verified"),
        "verified" => Some("cooling_off"),
        "cooling_off" => Some("processing"),
        _ => None,
    }
}

/// Customers may cancel while the request is not yet processing (point of no return).
pub fn can_cancel(current: &str) -> bool {
    matches!(current, "requested" | "verified" | "cooling_off")
}

/// Operators may reject any non-terminal request that has not begun processing.
pub fn can_reject(current: &str) -> bool {
    matches!(current, "requested" | "verified" | "cooling_off")
}

/// Execution (anonymization) is only valid from `processing`.
pub fn can_execute(current: &str) -> bool {
    current == "processing"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_path_is_linear() {
        assert_eq!(next_state("requested"), Some("verified"));
        assert_eq!(next_state("verified"), Some("cooling_off"));
        assert_eq!(next_state("cooling_off"), Some("processing"));
        for terminal in ["processing", "completed", "rejected", "canceled", "wat"] {
            assert_eq!(next_state(terminal), None, "{terminal}");
        }
    }

    #[test]
    fn cancel_and_reject_stop_at_processing() {
        for state in ["requested", "verified", "cooling_off"] {
            assert!(can_cancel(state), "{state}");
            assert!(can_reject(state), "{state}");
        }
        for state in ["processing", "completed", "rejected", "canceled"] {
            assert!(!can_cancel(state), "{state}");
            assert!(!can_reject(state), "{state}");
        }
    }

    #[test]
    fn execution_only_from_processing() {
        assert!(can_execute("processing"));
        for state in ["requested", "verified", "cooling_off", "completed"] {
            assert!(!can_execute(state), "{state}");
        }
    }
}
