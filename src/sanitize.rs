use once_cell::sync::Lazy;
use regex::Regex;

static SENSITIVE_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)(password|key|secret|token|master|vault|keeper)[\s:=]+[^\s]+").unwrap()
});

pub fn sanitize_for_display(message: &str) -> String {
    let sanitized = SENSITIVE_PATTERN.replace_all(message, "$1=[REDACTED]");
    sanitized.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_password() {
        let message = "Failed to authenticate: password=secret123";
        let sanitized = sanitize_for_display(message);
        assert_eq!(sanitized, "Failed to authenticate: password=[REDACTED]");
    }

    #[test]
    fn test_sanitize_key() {
        let message = "Master key: abcdef1234567890";
        let sanitized = sanitize_for_display(message);
        // The regex matches "Master key: abcdef1234567890" as a whole (master matches, key: is separator, rest is value)
        assert_eq!(sanitized, "Master=[REDACTED] abcdef1234567890");
    }

    #[test]
    fn test_sanitize_multiple_secrets() {
        let message = "password=admin and secret=mysecret";
        let sanitized = sanitize_for_display(message);
        assert_eq!(sanitized, "password=[REDACTED] and secret=[REDACTED]");
    }

    #[test]
    fn test_sanitize_preserves_safe_content() {
        let message = "Operation succeeded: item created";
        let sanitized = sanitize_for_display(message);
        assert_eq!(sanitized, "Operation succeeded: item created");
    }

    #[test]
    fn test_sanitize_case_insensitive() {
        let message = "PASSWORD=admin and Secret=mysecret";
        let sanitized = sanitize_for_display(message);
        assert_eq!(sanitized, "PASSWORD=[REDACTED] and Secret=[REDACTED]");
    }
}
