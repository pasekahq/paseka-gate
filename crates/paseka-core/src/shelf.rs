//! Shelves (PROTOCOL §9.3). The agent sends a pointer; the gate checks it here and then reads
//! the bytes itself. A doc that does not exist and a doc not open to the peer look the same.

use std::collections::BTreeSet;

use paseka_proto::tools::ShareInput;
use paseka_proto::{DocId, ShelfId};

/// A shelf: an owner-defined collection of documents.
#[derive(Debug, Clone)]
pub struct Shelf {
    /// Shelf id.
    pub id: ShelfId,
    /// Documents on it.
    pub docs: BTreeSet<DocId>,
}

/// A refused share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareError {
    /// `not_found`: no such doc, or not on a shelf open to the recipient.
    NotFound,
    /// `invalid_input`: the note breaks the note rules.
    BadNote,
}

const NOTE_MIN_BLOB: usize = 16;
const NOTE_MIN_DIGITS: usize = 6;

fn runs(s: &str, pred: impl Fn(char) -> bool) -> impl Iterator<Item = &str> {
    s.split(move |c: char| !pred(c)).filter(|r| !r.is_empty())
}

/// The note rule of PROTOCOL §5.2: no URLs or e-mail addresses, no base64 or hex runs of 16 or
/// more characters, no digit runs of 6 or more. Length and line rules are checked on input.
pub fn note_ok(note: &str) -> bool {
    let lower = note.to_ascii_lowercase();
    let linky = lower.contains("://")
        || lower.contains("www.")
        || note.contains('@')
        || !crate::risk::structural(note).is_empty();
    let digits = runs(note, |c| c.is_ascii_digit()).any(|r| r.len() >= NOTE_MIN_DIGITS);
    let blob = runs(note, |c| {
        c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_')
    })
    .filter(|r| r.len() >= NOTE_MIN_BLOB)
    .any(|r| {
        let digit = r.bytes().any(|b| b.is_ascii_digit());
        let sym = r
            .bytes()
            .any(|b| matches!(b, b'+' | b'/' | b'=' | b'-' | b'_'));
        let upper = r.bytes().any(|b| b.is_ascii_uppercase());
        let lower = r.bytes().any(|b| b.is_ascii_lowercase());
        digit || sym || (upper && lower && r.len() >= 24)
    });
    !(linky || digits || blob)
}

/// Checks a share against the shelves of the tenant and the shelves open to the recipient
/// through active T2 mandates. Returns the shelf holding the doc.
///
/// # Errors
/// [`ShareError`] when the doc is not shareable or the note is not allowed.
pub fn check_share<'a>(
    shelves: &'a [Shelf],
    open: &BTreeSet<&ShelfId>,
    input: &ShareInput,
) -> Result<&'a ShelfId, ShareError> {
    let shelf = shelves
        .iter()
        .find(|s| open.contains(&s.id) && s.docs.contains(&input.doc))
        .ok_or(ShareError::NotFound)?;
    if input.note.as_deref().is_some_and(|n| !note_ok(n)) {
        return Err(ShareError::BadNote);
    }
    Ok(&shelf.id)
}

#[cfg(test)]
mod tests {
    use paseka_proto::tools::ToolCall;

    use super::*;

    fn doc(i: u8) -> DocId {
        DocId::new(format!("doc_01JD{i:0>22}")).unwrap()
    }

    fn shelf(i: u8) -> ShelfId {
        ShelfId::new(format!("sh_01JD{i:0>22}")).unwrap()
    }

    fn share(d: &DocId, note: Option<&str>) -> ShareInput {
        let mut v = serde_json::json!({"to": "bob", "doc": d.as_str()});
        if let Some(n) = note {
            v["note"] = n.into();
        }
        match ToolCall::parse("share", v.to_string().as_bytes()).unwrap() {
            ToolCall::Share(s) => s,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn only_docs_on_open_shelves_are_shareable() {
        let shelves = [
            Shelf {
                id: shelf(1),
                docs: [doc(1)].into(),
            },
            Shelf {
                id: shelf(2),
                docs: [doc(2)].into(),
            },
        ];
        let s1 = shelf(1);
        let open: BTreeSet<&ShelfId> = [&s1].into();
        assert_eq!(
            check_share(&shelves, &open, &share(&doc(1), None)),
            Ok(&shelf(1))
        );
        assert_eq!(
            check_share(&shelves, &open, &share(&doc(2), None)),
            Err(ShareError::NotFound)
        );
        assert_eq!(
            check_share(&shelves, &open, &share(&doc(3), None)),
            Err(ShareError::NotFound)
        );
    }

    #[test]
    fn notes_cannot_carry_links_blobs_or_numbers() {
        assert!(note_ok("Section on pricing, as discussed."));
        for bad in [
            "see https://example.org/x",
            "mail bob@example.org",
            "code 123456",
            "aGVsbG8gd29ybGQ1",
            "deadbeef0123456789",
        ] {
            assert!(!note_ok(bad), "{bad}");
        }
    }
}
