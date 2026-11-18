//! Shelves: collections of the owner's library opened to peers. The agent sends a pointer; the
//! gate checks it here and then reads the bytes itself.

use std::collections::BTreeSet;

use paseka_proto::tools::ShareArgs;
use paseka_proto::{DocId, PeerId};

use crate::risk;

/// Longest agent note on a share, in characters.
pub const MAX_NOTE_CHARS: usize = 200;
/// Longest section name, in characters.
pub const MAX_SECTION_CHARS: usize = 128;

/// One shelf: documents under some path prefixes, open to some peers.
#[derive(Debug, Clone, Default)]
pub struct Shelf {
    /// Path prefixes, matched by whole segments.
    pub prefixes: Vec<DocId>,
    /// Peers the shelf is open to.
    pub open_to: BTreeSet<PeerId>,
}

/// Why a share pointer is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareError {
    /// The document is on no shelf open to the recipient.
    NotOnOpenShelf,
    /// The note is too long or carries structural content.
    BadNote,
    /// The section name is too long or has control characters.
    BadSection,
}

fn under(doc: &DocId, prefix: &DocId) -> bool {
    let (d, p) = (doc.as_str(), prefix.as_str());
    d == p || d.strip_prefix(p).is_some_and(|rest| rest.starts_with('/'))
}

/// Checks a share pointer against `shelves`. The returned document is what the gate may read.
///
/// # Errors
/// [`ShareError`] naming the failed check.
pub fn check_share<'a>(shelves: &[Shelf], args: &'a ShareArgs) -> Result<&'a DocId, ShareError> {
    let open = shelves
        .iter()
        .any(|s| s.open_to.contains(&args.to) && s.prefixes.iter().any(|p| under(&args.doc, p)));
    if !open {
        return Err(ShareError::NotOnOpenShelf);
    }
    if let Some(note) = &args.note {
        if note.chars().count() > MAX_NOTE_CHARS || !risk::structural(note).is_empty() {
            return Err(ShareError::BadNote);
        }
    }
    if let Some(section) = &args.section {
        if section.chars().count() > MAX_SECTION_CHARS || section.chars().any(char::is_control) {
            return Err(ShareError::BadSection);
        }
    }
    Ok(&args.doc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::peer;

    fn shelves() -> Vec<Shelf> {
        vec![Shelf {
            prefixes: vec![DocId::new("projects").unwrap()],
            open_to: [peer("bob")].into(),
        }]
    }

    fn args(to: &str, doc: &str, note: Option<&str>) -> ShareArgs {
        ShareArgs {
            to: peer(to),
            doc: DocId::new(doc).unwrap(),
            section: None,
            note: note.map(Into::into),
        }
    }

    #[test]
    fn share_is_allowed_only_on_a_shelf_open_to_that_peer() {
        assert!(check_share(&shelves(), &args("bob", "projects/paseka.md", None)).is_ok());
        assert_eq!(
            check_share(&shelves(), &args("carol", "projects/paseka.md", None)),
            Err(ShareError::NotOnOpenShelf)
        );
        assert_eq!(
            check_share(&shelves(), &args("bob", "family/notes.md", None)),
            Err(ShareError::NotOnOpenShelf)
        );
        assert_eq!(
            check_share(&shelves(), &args("bob", "projects-private/x.md", None)),
            Err(ShareError::NotOnOpenShelf)
        );
    }

    #[test]
    fn note_cannot_smuggle_links_blobs_or_length() {
        assert!(
            check_share(
                &shelves(),
                &args("bob", "projects/a.md", Some("the design notes"))
            )
            .is_ok()
        );
        for bad in ["see https://example.org/x", "4111 1111 1111 1111"] {
            assert_eq!(
                check_share(&shelves(), &args("bob", "projects/a.md", Some(bad))),
                Err(ShareError::BadNote),
                "{bad}"
            );
        }
        let long = "a".repeat(MAX_NOTE_CHARS + 1);
        assert_eq!(
            check_share(&shelves(), &args("bob", "projects/a.md", Some(&long))),
            Err(ShareError::BadNote)
        );
    }
}
