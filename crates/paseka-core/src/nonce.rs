//! Gate-issued single-use nonces, each bound to one tenant, recipient and content digest.

use paseka_proto::{Nonce, PeerId, Sha256, TenantId, UnixSecs};

use crate::tenant::TenantMap;

/// What a nonce was issued for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    /// Recipient of the draft.
    pub to: PeerId,
    /// Digest of the draft text when the approval request was shown.
    pub content_sha256: Sha256,
}

#[derive(Debug, Clone)]
struct Entry {
    binding: Binding,
    exp: UnixSecs,
    used: bool,
}

/// Why a nonce cannot be consumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceError {
    /// Never issued for this tenant.
    Unknown,
    /// Already consumed.
    Used,
    /// Past its expiry.
    Expired,
    /// Issued for another recipient or another text.
    BindingMismatch,
}

/// Issued nonces, partitioned by tenant.
#[derive(Debug, Clone, Default)]
pub struct NonceBook {
    entries: TenantMap<Nonce, Entry>,
}

impl NonceBook {
    /// Records a nonce issued for `binding`, valid until `exp`.
    pub fn issue(&mut self, tenant: &TenantId, nonce: Nonce, binding: Binding, exp: UnixSecs) {
        self.entries.insert(
            tenant,
            nonce,
            Entry {
                binding,
                exp,
                used: false,
            },
        );
    }

    /// Checks `nonce` without consuming it.
    ///
    /// # Errors
    /// [`NonceError`] when the nonce cannot be consumed now for `binding`.
    pub fn check(
        &self,
        tenant: &TenantId,
        nonce: &Nonce,
        binding: &Binding,
        now: UnixSecs,
    ) -> Result<(), NonceError> {
        let e = self.entries.get(tenant, nonce).ok_or(NonceError::Unknown)?;
        if e.used {
            return Err(NonceError::Used);
        }
        if now >= e.exp {
            return Err(NonceError::Expired);
        }
        if &e.binding != binding {
            return Err(NonceError::BindingMismatch);
        }
        Ok(())
    }

    /// Checks and consumes `nonce`; a second call for the same nonce fails with
    /// [`NonceError::Used`].
    ///
    /// # Errors
    /// As [`NonceBook::check`].
    pub fn consume(
        &mut self,
        tenant: &TenantId,
        nonce: &Nonce,
        binding: &Binding,
        now: UnixSecs,
    ) -> Result<(), NonceError> {
        self.check(tenant, nonce, binding, now)?;
        if let Some(e) = self.entries.get_mut(tenant, nonce) {
            e.used = true;
        }
        Ok(())
    }

    /// Drops entries expired at `now`. A used nonce stays until expiry so a replay still reads
    /// as [`NonceError::Used`] while the mandate could otherwise be valid.
    pub fn prune(&mut self, now: UnixSecs) {
        self.entries.retain(|_, e| now < e.exp);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::{nonce, peer, tenant};

    fn binding(text: &str) -> Binding {
        Binding {
            to: peer("bob"),
            content_sha256: crate::hash::content_sha256(text),
        }
    }

    #[test]
    fn nonce_is_single_use_tenant_bound_and_expires() {
        let mut book = NonceBook::default();
        let (alice, n) = (tenant("alice"), nonce(1));
        book.issue(&alice, n.clone(), binding("hi"), 100);
        assert_eq!(
            book.consume(&tenant("carol"), &n, &binding("hi"), 10),
            Err(NonceError::Unknown)
        );
        assert_eq!(
            book.consume(&alice, &n, &binding("hi!"), 10),
            Err(NonceError::BindingMismatch)
        );
        assert_eq!(
            book.consume(&alice, &n, &binding("hi"), 100),
            Err(NonceError::Expired)
        );
        assert_eq!(book.consume(&alice, &n, &binding("hi"), 10), Ok(()));
        assert_eq!(
            book.consume(&alice, &n, &binding("hi"), 11),
            Err(NonceError::Used)
        );
        book.prune(100);
        assert_eq!(
            book.check(&alice, &n, &binding("hi"), 11),
            Err(NonceError::Unknown)
        );
    }
}
