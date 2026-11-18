//! Template field validation (PROTOCOL §9.2). The gate renders owner templates; the agent
//! supplies only field values, and each value is checked against its typed field.

use paseka_proto::tools::{FieldSpec, FieldType, FieldValue};

const SHORT_TEXT_MAX_DIGITS: usize = 5;

fn short_text_ok(s: &str, max_len: usize) -> bool {
    let charset = s
        .chars()
        .all(|c| c.is_alphanumeric() || c == ' ' || ".,:;!?'()-".contains(c));
    let mut run = 0usize;
    let mut longest = 0usize;
    for c in s.chars() {
        run = if c.is_ascii_digit() { run + 1 } else { 0 };
        longest = longest.max(run);
    }
    !s.is_empty()
        && s.chars().count() <= max_len
        && charset
        && longest <= SHORT_TEXT_MAX_DIGITS
        && crate::risk::structural(s).is_empty()
}

fn date_ok(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b.iter()
            .enumerate()
            .all(|(i, c)| i == 4 || i == 7 || c.is_ascii_digit())
        && s[5..7].parse::<u8>().is_ok_and(|m| (1..=12).contains(&m))
        && s[8..10].parse::<u8>().is_ok_and(|d| (1..=31).contains(&d))
}

/// Whether `value` is valid for `spec`. Unknown field types never validate.
pub fn field_ok(spec: &FieldSpec, value: &FieldValue) -> bool {
    match (spec.kind, value) {
        (FieldType::Enum, FieldValue::Text(s)) => spec.values.iter().any(|v| v == s),
        (FieldType::Int, FieldValue::Int(n)) => {
            spec.min.is_none_or(|m| *n >= m) && spec.max.is_none_or(|m| *n <= m)
        }
        (FieldType::Date, FieldValue::Text(s)) => date_ok(s),
        (FieldType::ShortText, FieldValue::Text(s)) => {
            short_text_ok(s, spec.max_len.map_or(64, |l| l as usize))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(kind: FieldType) -> FieldSpec {
        FieldSpec {
            kind,
            values: vec!["yes".into(), "no".into()],
            min: Some(1),
            max: Some(10),
            max_len: Some(40),
        }
    }

    fn text(s: &str) -> FieldValue {
        FieldValue::Text(s.into())
    }

    #[test]
    fn typed_fields_accept_only_their_values() {
        assert!(field_ok(&spec(FieldType::Enum), &text("yes")));
        assert!(!field_ok(&spec(FieldType::Enum), &text("maybe")));
        assert!(field_ok(&spec(FieldType::Int), &FieldValue::Int(3)));
        assert!(!field_ok(&spec(FieldType::Int), &FieldValue::Int(11)));
        assert!(field_ok(&spec(FieldType::Date), &text("2026-11-18")));
        assert!(!field_ok(&spec(FieldType::Date), &text("2026-13-01")));
        assert!(!field_ok(&spec(FieldType::Unknown), &text("yes")));
    }

    #[test]
    fn short_text_refuses_links_long_numbers_and_odd_characters() {
        let s = spec(FieldType::ShortText);
        assert!(field_ok(&s, &text("Tuesday afternoon, room 12")));
        for bad in [
            "see https://example.org/x",
            "call 5550109",
            "a<b>",
            "",
            "x\ny",
        ] {
            assert!(!field_ok(&s, &text(bad)), "{bad}");
        }
    }
}
