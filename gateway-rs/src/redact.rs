//! Redaction of PII before any external (LLM) call, per privacy rules.
//! Patterns are generic PII shapes only — no invented Indian-format specifics:
//! Aadhaar/PAN "like" patterns are matched as digit/alpha sequences and marked
//! by context words, so we never encode unverified official formats.

use regex::Regex;

pub struct Redactor {
    phone: Regex,
    card: Regex,
    email: Regex,
    account_ctx: Regex,
    id_ctx: Regex,
}

impl Default for Redactor {
    fn default() -> Self {
        // UNVERIFIED: exact Aadhaar/PAN official formats intentionally NOT
        // hardcoded (would be inventing a format). We redact long digit runs
        // and ID-context numbers instead.
        Self {
            phone: Regex::new(r"(?x)(?:\+?\d[\d\s-]{8,14}\d)").expect("static regex"),
            card: Regex::new(r"(?x)\b(?:\d[ -]?){13,19}\b").expect("static regex"),
            email: Regex::new(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}").expect("static regex"),
            account_ctx: Regex::new(
                r"(?i)(account\s*(?:no\.?|number)?|a\/c)\D{0,5}\d[\d\s/-]{5,}",
            )
            .expect("static regex"),
            id_ctx: Regex::new(r"(?i)(aadhaar|aadhar|pan)\s*(?:number|no\.?)?\s*[:\-]?\s*[A-Za-z0-9][A-Za-z0-9\s/-]{5,}").expect("static regex"),
        }
    }
}

impl Redactor {
    /// Replace PII with typed placeholders. Order matters: longer numeric
    /// structures first so phone doesn't partially eat a card number.
    pub fn redact(&self, text: &str) -> String {
        let out = self.card.replace_all(text, "[REDACTED_CARD]");
        let out = self.account_ctx.replace_all(&out, "[REDACTED_ACCOUNT]");
        let out = self.id_ctx.replace_all(&out, "[REDACTED_ID]");
        let out = self.email.replace_all(&out, "[REDACTED_EMAIL]");
        let out = self.phone.replace_all(&out, "[REDACTED_PHONE]");
        out.into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_phone_email_card() {
        let r = Redactor::default();
        let out = r.redact("Call 98765 43210 or +91 9876543210, mail me@x.com, card 4111 1111 1111 1111");
        assert!(out.contains("[REDACTED_PHONE]"), "{out}");
        assert!(out.contains("[REDACTED_EMAIL]"), "{out}");
        assert!(out.contains("[REDACTED_CARD]"), "{out}");
        assert!(!out.contains("98765"), "{out}");
        assert!(!out.contains("me@x.com"), "{out}");
    }
    #[test]
    fn redacts_context_ids() {
        let r = Redactor::default();
        let out = r.redact("your aadhaar 1234 5678 9012 and PAN ABCP1234X must be updated");
        assert!(out.contains("[REDACTED_ID]"), "{out}");
        assert!(!out.contains("1234 5678"), "{out}");
    }
    #[test]
    fn benign_text_unchanged() {
        let r = Redactor::default();
        let src = "Your OTP is 4321. Do not share it with anyone.";
        // OTP itself is short (4 digits) and has no PII context; keep behaviour
        // conservative: only >=9-digit runs are treated as phone-like.
        assert_eq!(r.redact(src), src);
    }
}
