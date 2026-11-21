//! Tenant isolation. Every stored object is keyed by its tenant; no accessor exists that reads
//! without naming the tenant, so a lookup can only ever see the caller's own tenant.

use std::collections::BTreeMap;

use paseka_proto::TenantId;

/// A map partitioned by tenant.
#[derive(Debug, Clone)]
pub struct TenantMap<K: Ord, V> {
    inner: BTreeMap<TenantId, BTreeMap<K, V>>,
}

impl<K: Ord, V> Default for TenantMap<K, V> {
    fn default() -> Self {
        Self {
            inner: BTreeMap::new(),
        }
    }
}

impl<K: Ord, V> TenantMap<K, V> {
    /// Inserts `value` under `key` in `tenant`'s partition, returning the previous value.
    pub fn insert(&mut self, tenant: &TenantId, key: K, value: V) -> Option<V> {
        self.inner
            .entry(tenant.clone())
            .or_default()
            .insert(key, value)
    }

    /// Reads `key` from `tenant`'s partition only.
    pub fn get(&self, tenant: &TenantId, key: &K) -> Option<&V> {
        self.inner.get(tenant)?.get(key)
    }

    /// The value of `key` in `tenant`, inserted as `V::default()` when absent.
    pub fn entry(&mut self, tenant: &TenantId, key: K) -> &mut V
    where
        V: Default,
    {
        self.inner
            .entry(tenant.clone())
            .or_default()
            .entry(key)
            .or_default()
    }

    /// Mutable access to `key` in `tenant`'s partition only.
    pub fn get_mut(&mut self, tenant: &TenantId, key: &K) -> Option<&mut V> {
        self.inner.get_mut(tenant)?.get_mut(key)
    }

    /// Keeps only entries for which `keep` holds, across all tenants.
    pub fn retain(&mut self, mut keep: impl FnMut(&K, &mut V) -> bool) {
        for part in self.inner.values_mut() {
            part.retain(|k, v| keep(k, v));
        }
        self.inner.retain(|_, part| !part.is_empty());
    }

    /// The entries of `tenant`'s partition only, in key order.
    pub fn iter(&self, tenant: &TenantId) -> impl Iterator<Item = (&K, &V)> {
        self.inner.get(tenant).into_iter().flatten()
    }

    /// Number of entries in `tenant`'s partition.
    pub fn len(&self, tenant: &TenantId) -> usize {
        self.inner.get(tenant).map_or(0, BTreeMap::len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::tenant;

    #[test]
    fn a_key_stored_for_one_tenant_is_invisible_to_another() {
        let mut m = TenantMap::default();
        m.insert(&tenant(1), "draft-1", 1);
        assert_eq!(m.get(&tenant(1), &"draft-1"), Some(&1));
        assert_eq!(m.get(&tenant(2), &"draft-1"), None);
        assert!(m.get_mut(&tenant(2), &"draft-1").is_none());
        assert_eq!(m.len(&tenant(2)), 0);
    }
}
