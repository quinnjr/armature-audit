//! Data masking for sensitive information

use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::Value;
use std::borrow::Cow;

/// Field-name fragments that identify high-sensitivity identifiers (SSNs, card
/// numbers, and similar). For these, even the last few characters are abused
/// (e.g. the last four of an SSN), so field-name masking reveals *zero*
/// trailing characters regardless of the configured `show_last_chars`.
const IDENTITY_FIELDS: &[&str] = &[
    "ssn",
    "social_security",
    "credit_card",
    "creditcard",
    "card_number",
    "cvv",
    "pin",
];

/// Field-name fragments that identify credentials (passwords, tokens, keys).
/// Any trailing characters of a credential help an attacker (and confirm a
/// guess), so these — like [`IDENTITY_FIELDS`] — are masked completely
/// regardless of the configured `show_last_chars`.
const CREDENTIAL_FIELDS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "api-key",
    "bearer",
    "authorization",
    "auth",
    "private_key",
    "privatekey",
    "cookie",
    "session",
];

/// Fields to mask by default
pub const DEFAULT_MASKED_FIELDS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "api-key",
    "access_token",
    "refresh_token",
    "bearer",
    "authorization",
    "auth",
    "credit_card",
    "creditcard",
    "card_number",
    "cvv",
    "ssn",
    "social_security",
    "pin",
    "private_key",
    "privatekey",
    "cookie",
    "session",
];

/// Regular expressions for masking patterns
static EMAIL_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap());

static PHONE_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b").unwrap());

// Matches both the hyphenated `123-45-6789` form and a bare 9-digit run
// `123456789` so a dashless SSN is not left in the clear.
static SSN_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(?:\d{3}-\d{2}-\d{4}|\d{9})\b").unwrap());

// Matches 13–19 digit card numbers (Visa/MC 16, Amex 15, Diners 14, and the
// 13/19-digit extremes) with optional single space/hyphen group separators.
static CREDIT_CARD_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b\d(?:[- ]?\d){12,18}\b").unwrap());

/// Data masking configuration
#[derive(Debug, Clone)]
pub struct MaskingConfig {
    /// Fields to mask
    pub masked_fields: Vec<String>,

    /// Mask email addresses
    pub mask_emails: bool,

    /// Mask phone numbers
    pub mask_phones: bool,

    /// Mask SSNs
    pub mask_ssn: bool,

    /// Mask credit cards
    pub mask_credit_cards: bool,

    /// Mask character (default: '*')
    pub mask_char: char,

    /// Show last N characters of a masked value.
    ///
    /// Defaults to `0`. Never applied to credential fields (passwords, tokens,
    /// keys, …) or identity fields (SSN, card, …), which are always masked
    /// completely; it only affects custom fields added with
    /// [`MaskingConfig::add_field`].
    pub show_last_chars: usize,
}

impl Default for MaskingConfig {
    fn default() -> Self {
        Self {
            masked_fields: DEFAULT_MASKED_FIELDS
                .iter()
                .map(|s| s.to_string())
                .collect(),
            mask_emails: true,
            mask_phones: true,
            mask_ssn: true,
            mask_credit_cards: true,
            mask_char: '*',
            show_last_chars: 0,
        }
    }
}

impl MaskingConfig {
    /// Create a new masking configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a field to mask
    pub fn add_field(mut self, field: impl Into<String>) -> Self {
        self.masked_fields.push(field.into());
        self
    }

    /// Set whether to mask emails
    pub fn mask_emails(mut self, mask: bool) -> Self {
        self.mask_emails = mask;
        self
    }

    /// Set whether to mask phone numbers
    pub fn mask_phones(mut self, mask: bool) -> Self {
        self.mask_phones = mask;
        self
    }

    /// Set mask character
    pub fn mask_char(mut self, c: char) -> Self {
        self.mask_char = c;
        self
    }

    /// Set number of characters to show at end
    pub fn show_last_chars(mut self, n: usize) -> Self {
        self.show_last_chars = n;
        self
    }
}

/// Mask sensitive data in a string
///
/// # Examples
///
/// ```
/// use armature_audit::*;
///
/// let config = MaskingConfig::default();
/// let masked = mask_string("password: secret123", &config);
/// // Result contains masked password
/// ```
pub fn mask_string(input: &str, config: &MaskingConfig) -> String {
    // Thread a `Cow` through the substitution chain so the dominant no-match
    // path never clones the body. `Regex::replace_all` returns `Cow::Borrowed`
    // when it made no replacement; only a real match materializes an owned
    // `String`, and subsequent stages keep operating on that same buffer.
    let mut result: Cow<str> = Cow::Borrowed(input);

    if config.mask_emails {
        result = apply_regex(result, &EMAIL_REGEX, "[EMAIL]");
    }

    if config.mask_phones {
        result = apply_regex(result, &PHONE_REGEX, "[PHONE]");
    }

    if config.mask_ssn {
        result = apply_regex(result, &SSN_REGEX, "[SSN]");
    }

    if config.mask_credit_cards {
        result = apply_regex(result, &CREDIT_CARD_REGEX, "[CARD]");
    }

    result.into_owned()
}

/// Apply one masking regex, preserving the input buffer when nothing matched.
///
/// If `replace_all` returns `Cow::Borrowed` no replacement occurred, so the
/// original `Cow` is returned untouched (no allocation). Only an actual match
/// (`Cow::Owned`) produces a new buffer.
fn apply_regex<'a>(input: Cow<'a, str>, regex: &Regex, replacement: &str) -> Cow<'a, str> {
    match regex.replace_all(&input, replacement) {
        Cow::Borrowed(_) => input,
        Cow::Owned(owned) => Cow::Owned(owned),
    }
}

/// Mask a value (show only last N characters)
///
/// # Examples
///
/// ```
/// use armature_audit::*;
///
/// let masked = mask_value("secret123", '*', 3);
/// assert_eq!(masked, "******123");
/// ```
pub fn mask_value(value: &str, mask_char: char, show_last: usize) -> String {
    // Count/slice by Unicode scalar values (chars), never by bytes, so a
    // multibyte secret (emoji, accented text, CJK, …) can never be sliced at a
    // mid-codepoint offset and panic.
    let total_chars = value.chars().count();

    if total_chars <= show_last {
        return std::iter::repeat_n(mask_char, total_chars).collect();
    }

    let masked_len = total_chars - show_last;
    let mut result: String = std::iter::repeat_n(mask_char, masked_len).collect();
    result.extend(value.chars().skip(masked_len));

    result
}

/// Mask sensitive fields in JSON
///
/// # Examples
///
/// ```
/// use armature_audit::*;
/// use serde_json::json;
///
/// let config = MaskingConfig::default();
/// let data = json!({
///     "username": "alice",
///     "password": "secret123"
/// });
///
/// let masked = mask_json(&data, &config);
/// // password field will be masked
/// ```
pub fn mask_json(value: &Value, config: &MaskingConfig) -> Value {
    // Precompute the lowercased matcher set once for the whole (recursive)
    // traversal instead of lowercasing every configured field for every key.
    let matchers: Vec<String> = config
        .masked_fields
        .iter()
        .map(|f| f.to_lowercase())
        .collect();
    mask_json_inner(value, config, &matchers)
}

fn mask_json_inner(value: &Value, config: &MaskingConfig, matchers: &[String]) -> Value {
    match value {
        Value::Object(map) => {
            let mut masked_map = serde_json::Map::new();

            for (key, val) in map {
                let key_lower = key.to_lowercase();

                // Check if this field should be masked
                let should_mask = matchers
                    .iter()
                    .any(|field| key_lower.contains(field.as_str()));

                if should_mask {
                    if let Value::String(s) = val {
                        // For high-sensitivity identifiers (SSN, card, …) reveal
                        // zero trailing characters — the last four digits are
                        // exactly what an attacker wants — regardless of the
                        // configured `show_last_chars`.
                        let show_last = if is_fully_masked_field(&key_lower) {
                            0
                        } else {
                            config.show_last_chars
                        };
                        masked_map.insert(
                            key.clone(),
                            Value::String(mask_value(s, config.mask_char, show_last)),
                        );
                    } else {
                        masked_map.insert(key.clone(), Value::String("[REDACTED]".to_string()));
                    }
                } else {
                    // Recursively mask nested objects
                    masked_map.insert(key.clone(), mask_json_inner(val, config, matchers));
                }
            }

            Value::Object(masked_map)
        }
        Value::Array(arr) => Value::Array(
            arr.iter()
                .map(|v| mask_json_inner(v, config, matchers))
                .collect(),
        ),
        Value::String(s) => Value::String(mask_string(s, config)),
        _ => value.clone(),
    }
}

/// Whether a (lowercased) field name denotes a credential or high-sensitivity
/// identifier whose trailing characters must never be revealed.
fn is_fully_masked_field(key_lower: &str) -> bool {
    IDENTITY_FIELDS
        .iter()
        .chain(CREDENTIAL_FIELDS)
        .any(|field| key_lower.contains(field))
}

/// Whether a (lowercased) key matches one of the configured masked fields.
fn is_masked_key(key_lower: &str, matchers: &[String]) -> bool {
    matchers
        .iter()
        .any(|field| key_lower.contains(field.as_str()))
}

/// Placeholder written in place of a body that looked structured but could
/// not be parsed, so key-based masking was impossible.
pub const UNPARSEABLE_BODY_PLACEHOLDER: &str = "[REDACTED: unparseable structured body]";

/// Mask sensitive data in a text body.
///
/// - **JSON** is parsed and masked by key ([`mask_json`]).
/// - A body that *looks* like JSON (starts with `{` or `[`) but does not
///   parse is replaced entirely with [`UNPARSEABLE_BODY_PLACEHOLDER`]: its
///   keys cannot be trusted to be found by pattern matching.
/// - **`application/x-www-form-urlencoded`**-shaped bodies (`a=1&b=2`) are
///   masked by key ([`mask_form`]).
/// - Anything else gets `key: value` / `key=value` masking for the configured
///   fields, then the PII patterns ([`mask_string`]).
///
/// # Examples
///
/// ```
/// use armature_audit::*;
///
/// let config = MaskingConfig::default();
/// let masked = mask_body("user=alice&password=hunter2", &config);
/// assert!(!masked.contains("hunter2"));
/// assert!(masked.contains("user=alice"));
/// ```
pub fn mask_body(body: &str, config: &MaskingConfig) -> String {
    let trimmed = body.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return match serde_json::from_str::<Value>(body) {
            Ok(json) => {
                let masked = mask_json(&json, config);
                serde_json::to_string(&masked)
                    .unwrap_or_else(|_| UNPARSEABLE_BODY_PLACEHOLDER.to_string())
            }
            Err(_) => UNPARSEABLE_BODY_PLACEHOLDER.to_string(),
        };
    }

    if looks_form_encoded(body) {
        return mask_form(body, config);
    }

    mask_string(&mask_key_values(body, config), config)
}

/// Heuristic: a non-empty body with no whitespace whose every `&`-separated
/// pair contains `=`.
fn looks_form_encoded(body: &str) -> bool {
    !body.is_empty()
        && !body.contains(char::is_whitespace)
        && body
            .split('&')
            .all(|pair| pair.is_empty() || pair.contains('='))
        && body.contains('=')
}

/// Mask an `application/x-www-form-urlencoded` body by key.
///
/// The value of every pair whose (percent-decoded, lowercased) key matches a
/// configured masked field is replaced with `[REDACTED]`; other values are
/// percent-decoded and run through the PII patterns, and replaced only if a
/// pattern matched.
///
/// # Examples
///
/// ```
/// use armature_audit::*;
///
/// let masked = mask_form("user=alice&api_key=sk_live_1", &MaskingConfig::default());
/// assert_eq!(masked, "user=alice&api_key=[REDACTED]");
/// ```
pub fn mask_form(body: &str, config: &MaskingConfig) -> String {
    let matchers: Vec<String> = config
        .masked_fields
        .iter()
        .map(|f| f.to_lowercase())
        .collect();

    body.split('&')
        .map(|pair| {
            let Some((key, value)) = pair.split_once('=') else {
                return pair.to_string();
            };
            let key_lower = percent_decode(key).to_lowercase();
            if is_masked_key(&key_lower, &matchers) {
                return format!("{key}=[REDACTED]");
            }
            let decoded = percent_decode(value);
            let masked = mask_string(&decoded, config);
            if masked == decoded {
                pair.to_string()
            } else {
                format!("{key}={masked}")
            }
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Lossy `application/x-www-form-urlencoded` decoding (`+` → space, `%XX`).
fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(b) => {
                        out.push(b);
                        i += 2;
                    }
                    None => out.push(b'%'),
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Redact the value in `key: value` / `key=value` occurrences of a configured
/// masked field inside free text (e.g. `password: hunter2`,
/// `Authorization: Bearer abc`).
fn mask_key_values(input: &str, config: &MaskingConfig) -> String {
    let alternation = config
        .masked_fields
        .iter()
        .map(|f| regex::escape(f))
        .collect::<Vec<_>>()
        .join("|");
    if alternation.is_empty() {
        return input.to_string();
    }
    let pattern = format!(
        r#"(?i)([\w-]*(?:{alternation})[\w-]*"?\s*[:=]\s*)(?:(?:bearer|basic)\s+)?("[^"]*"|[^\s,;&]+)"#
    );
    match Regex::new(&pattern) {
        Ok(re) => re.replace_all(input, "${1}[REDACTED]").into_owned(),
        // A field list that does not compile cannot be honoured; do not
        // return the input unmasked.
        Err(_) => UNPARSEABLE_BODY_PLACEHOLDER.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_mask_value() {
        assert_eq!(mask_value("secret123", '*', 3), "******123");
        assert_eq!(mask_value("abc", '*', 3), "***");
        assert_eq!(mask_value("ab", '*', 3), "**");
    }

    #[test]
    fn test_mask_value_multibyte_no_panic() {
        // Each 🔒 is 4 bytes; a byte-based slice at masked_len would fall in the
        // middle of a codepoint and panic. Char-based masking must not.
        let masked = mask_value("🔒🔒🔒🔒🔒", '*', 2);
        assert_eq!(masked, "***🔒🔒");
        // 3 masked chars + 2 visible chars = 5 chars total.
        assert_eq!(masked.chars().count(), 5);

        // Mixed multibyte secret masked entirely except last char.
        let masked = mask_value("café☕", '*', 1);
        assert_eq!(masked, "****☕");

        // show_last larger than the (char) length: fully masked, no panic.
        let masked = mask_value("naïve", '*', 10);
        assert_eq!(masked, "*****");
    }

    #[test]
    fn test_mask_email() {
        let config = MaskingConfig::default();
        let masked = mask_string("Email: user@example.com", &config);
        assert!(masked.contains("[EMAIL]"));
        assert!(!masked.contains("user@example.com"));
    }

    #[test]
    fn test_mask_phone() {
        let config = MaskingConfig::default();
        let masked = mask_string("Phone: 123-456-7890", &config);
        assert!(masked.contains("[PHONE]"));
    }

    #[test]
    fn test_mask_json_password() {
        let config = MaskingConfig::default();
        let data = json!({
            "username": "alice",
            "password": "secret123"
        });

        let masked = mask_json(&data, &config);
        assert_eq!(masked["username"], "alice");
        assert_ne!(masked["password"], "secret123");
        assert!(masked["password"].as_str().unwrap().contains("*"));
    }

    #[test]
    fn test_mask_json_nested() {
        let config = MaskingConfig::default();
        let data = json!({
            "user": {
                "name": "alice",
                "password": "secret123"
            }
        });

        let masked = mask_json(&data, &config);
        assert_eq!(masked["user"]["name"], "alice");
        assert_ne!(masked["user"]["password"], "secret123");
    }

    #[test]
    fn test_mask_json_array() {
        let config = MaskingConfig::default();
        let data = json!([
            {"username": "alice", "password": "secret1"},
            {"username": "bob", "password": "secret2"}
        ]);

        let masked = mask_json(&data, &config);
        assert_eq!(masked[0]["username"], "alice");
        assert_ne!(masked[0]["password"], "secret1");
    }

    #[test]
    fn test_mask_body_json() {
        let config = MaskingConfig::default();
        let body = r#"{"username":"alice","password":"secret123"}"#;
        let masked = mask_body(body, &config);
        assert!(masked.contains("alice"));
        assert!(!masked.contains("secret123"));
    }

    #[test]
    fn test_mask_ssn_dashless() {
        // A bare 9-digit SSN must be masked, not just the hyphenated form.
        let config = MaskingConfig::default();
        let masked = mask_string("SSN: 123456789 done", &config);
        assert!(masked.contains("[SSN]"), "dashless SSN masked: {masked}");
        assert!(!masked.contains("123456789"));

        // The hyphenated form keeps working.
        let masked = mask_string("SSN: 123-45-6789", &config);
        assert!(masked.contains("[SSN]"));
        assert!(!masked.contains("123-45-6789"));
    }

    #[test]
    fn test_mask_credit_card_variable_length() {
        let config = MaskingConfig::default();

        // 15-digit Amex (4-6-5 grouping).
        let masked = mask_string("Card 3782 822463 10005", &config);
        assert!(masked.contains("[CARD]"), "amex masked: {masked}");
        assert!(!masked.contains("822463"));

        // 14-digit Diners.
        let masked = mask_string("Card 3056 930902 5904", &config);
        assert!(masked.contains("[CARD]"), "diners masked: {masked}");

        // Classic 16-digit still masked.
        let masked = mask_string("Card 4111 1111 1111 1111", &config);
        assert!(masked.contains("[CARD]"));
        assert!(!masked.contains("4111"));
    }

    #[test]
    fn test_mask_json_identity_field_hides_last_four() {
        // Field-name masking of an SSN must NOT reveal the last four digits,
        // even with the default show_last_chars = 4.
        let config = MaskingConfig::default();
        let data = json!({ "ssn": "123-45-6789", "card_number": "4111111111111111" });
        let masked = mask_json(&data, &config);

        let ssn = masked["ssn"].as_str().unwrap();
        assert!(!ssn.contains("6789"), "SSN last-4 leaked: {ssn}");
        assert!(ssn.chars().all(|c| c == '*'), "SSN fully masked: {ssn}");

        let card = masked["card_number"].as_str().unwrap();
        assert!(!card.contains("1111"), "card tail leaked: {card}");
        assert!(card.chars().all(|c| c == '*'));
    }

    #[test]
    fn test_mask_json_credentials_never_reveal_tail() {
        // Credentials reveal nothing, even with a non-zero show_last_chars.
        let config = MaskingConfig::default().show_last_chars(4);
        let data = json!({ "password": "secret123", "access_token": "tok_abcd" });
        let masked = mask_json(&data, &config);
        let pw = masked["password"].as_str().unwrap();
        assert!(pw.chars().all(|c| c == '*'), "password fully masked: {pw}");
        let tok = masked["access_token"].as_str().unwrap();
        assert!(tok.chars().all(|c| c == '*'), "token fully masked: {tok}");
    }

    #[test]
    fn test_custom_field_keeps_configured_tail() {
        let config = MaskingConfig::default()
            .add_field("account_number")
            .show_last_chars(2);
        let masked = mask_json(&json!({ "account_number": "12345678" }), &config);
        assert_eq!(masked["account_number"], "******78");
    }

    #[test]
    fn test_default_show_last_chars_is_zero() {
        assert_eq!(MaskingConfig::default().show_last_chars, 0);
    }

    #[test]
    fn test_mask_body_form_encoded() {
        let config = MaskingConfig::default();
        let masked = mask_body(
            "username=alice&password=hunter2&refresh%5Ftoken=rt_123&email=a%40b.com",
            &config,
        );
        assert!(masked.contains("username=alice"), "{masked}");
        assert!(!masked.contains("hunter2"), "{masked}");
        assert!(!masked.contains("rt_123"), "{masked}");
        assert!(masked.contains("email=[EMAIL]"), "{masked}");
    }

    #[test]
    fn test_mask_body_unparseable_json_is_redacted() {
        let config = MaskingConfig::default();
        let masked = mask_body(r#"{"password":"hunter2","x":"#, &config);
        assert_eq!(masked, UNPARSEABLE_BODY_PLACEHOLDER);
    }

    #[test]
    fn test_mask_body_text_key_values() {
        let config = MaskingConfig::default();
        let masked = mask_body(
            "login password: hunter2 Authorization: Bearer abc.def.ghi user=bob",
            &config,
        );
        assert!(!masked.contains("hunter2"), "{masked}");
        assert!(!masked.contains("abc.def.ghi"), "{masked}");
        assert!(masked.contains("user=bob"), "{masked}");
    }

    #[test]
    fn test_mask_body_text() {
        let config = MaskingConfig::default();
        let body = "Email: user@example.com, Phone: 123-456-7890";
        let masked = mask_body(body, &config);
        assert!(masked.contains("[EMAIL]"));
        assert!(masked.contains("[PHONE]"));
    }
}
