//! LEZ v0.4 target chain for the operator loop: a thin `Chain` impl over `lez_client::LezClient`.
use crate::{
    material::UpdateMaterial,
    operator::{Chain, TxRef, View},
};
use anyhow::Result;
pub use lez_client::{now_slot, LezClient as LezChain};

impl Chain for LezChain {
    fn view(&self) -> Result<View> {
        let s = self.instance()?.store;
        Ok(View {
            period: s.period(),
            finalized_slot: s.finalized_header.beacon.slot,
            next_known: s.next_sync_committee.is_some(),
        })
    }

    fn submit_update(&self, m: UpdateMaterial) -> Result<TxRef> {
        let raw = m.updates.into_iter().next().unwrap_or(m.finality_update);
        self.submit_update_json(&raw).map(TxRef)
    }
}
