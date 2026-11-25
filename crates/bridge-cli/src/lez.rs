//! LEZ side over the v0.4.0-rc1 wallet (`LEE_WALLET_HOME_DIR`): deploys, signed public txs (config,
//! admin, freeze, attest Init/Update), privacy-preserving root calls on holders' private accounts
//! (claim, transfer, burn) and the pending-credit receive. Proofs follow `RISC0_DEV_MODE`.

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, Result};
use borsh::BorshSerialize;
use common::transaction::LeeTransaction;
use lee::privacy_preserving_transaction::circuit::ProgramCatalog;
use lee::program::Program;
use lee::public_transaction::{Message, WitnessSet};
use lee::{AccountId, Actor, PublicAccountEvidence, PublicTransaction};
use lee_core::program::PdaSeed;
use program_loader_core::MAX_SEGMENT_DATA_LEN;
use sequencer_service_rpc::RpcClient as _;
use wallet::program_facades::program_loader::ProgramLoader;
use wallet::{AccountIdentity, AccountMention, AsyncDelivery, PendingMessage, WalletCore};

pub type Wallet = WalletCore<sequencer_service_rpc::SequencerClient>;

pub struct Lez {
    pub w: Wallet,
    /// Fee payer of public txs (and default signer).
    pub payer: AccountId,
    pub bridge: AccountId,
    pub attest: AccountId,
}

/// An included LEZ tx.
#[derive(Debug, Clone)]
pub struct LezTx {
    pub hash: String,
    pub block: u64,
    pub ok: bool,
    /// borsh of the included transaction (public footprint, for the leak scan).
    pub bytes: Vec<u8>,
    pub public_actors: Vec<Actor>,
}

pub fn pda_mention(program: AccountId, seed: [u8; 32]) -> AccountMention {
    AccountIdentity::PublicPda {
        program,
        seed: PdaSeed::new(seed),
    }
    .select_program_actor_state(program)
}

fn ef(e: impl std::fmt::Debug) -> anyhow::Error {
    anyhow!("{e:?}")
}

/// The bridge holder of one LEZ wallet, all from the wallet mnemonic: the root (`/`) private
/// account, the b22 keys from that account's secret spending key, and the root public account
/// (its fee/funding account) with its public key.
pub struct WalletHolder {
    pub account: AccountId,
    pub keys: crate::Keys,
    pub public: AccountId,
    pub public_key: [u8; 32],
    /// How another wallet addresses this holder (sealed async messages, e.g. a bridge `Transfer`).
    pub foreign: AccountIdentity,
}

pub fn wallet_holder(kc: &wallet::storage::key_chain::UserKeyChain) -> Result<WalletHolder> {
    let f = kc
        .private_accounts()
        .find(|f| f.chain_index.as_ref().is_some_and(|c| c.chain().is_empty()))
        .ok_or_else(|| anyhow!("wallet has no root private account"))?;
    let k = f.key_chain;
    let account =
        AccountId::for_private_account(&k.nullifier_public_key, &k.viewing_public_key, f.kind);
    let (public, _) = kc
        .public_account_ids()
        .find(|(_, c)| c.is_some_and(|c| c.chain().is_empty()))
        .ok_or_else(|| anyhow!("wallet has no root public account"))?;
    let sk = kc
        .pub_account_signing_key(public)
        .ok_or_else(|| anyhow!("no signing key for the root public account"))?;
    Ok(WalletHolder {
        account,
        keys: crate::Keys::from_lez_secret(&k.secret_spending_key.0),
        public,
        public_key: *lee::PublicKey::new_from_private_key(sk).value(),
        foreign: AccountIdentity::PrivateForeign {
            npk: k.nullifier_public_key.clone(),
            vpk: k.viewing_public_key.clone(),
            kind: f.kind.clone(),
        },
    })
}

/// A block's txs as `(reverted, public actors)`: does a live (non-reverted) one name `actor`, i.e.
/// that account under that program? A tx naming the account under another program (a dust native
/// transfer to the PDA address) does not count.
pub fn names_live(txs: &[(bool, Vec<Actor>)], actor: &Actor) -> bool {
    txs.iter().any(|(rev, a)| !rev && a.contains(actor))
}

impl Lez {
    pub fn open(payer: AccountId) -> Result<Self> {
        Self::open_at(
            &std::path::PathBuf::from(std::env::var("LEE_WALLET_HOME_DIR")?),
            payer,
        )
    }

    /// The wallet at `home` (`wallet_config.json` + `storage.json`, unencrypted).
    pub fn open_at(home: &std::path::Path, payer: AccountId) -> Result<Self> {
        let w = if home.join("storage.json").exists() {
            WalletCore::new_update_chain(
                home.join("wallet_config.json"),
                home.join("storage.json"),
                None,
                "",
            )
            .map_err(ef)?
        } else {
            // a reader (e.g. the root signer on signer host 2) gets a fresh empty wallet: no keys copied around
            let (w, _) = WalletCore::new_init_storage(
                home.join("wallet_config.json"),
                home.join("storage.json"),
                None,
                "",
            )
            .map_err(ef)?;
            w.store_persistent_data().map_err(ef)?;
            w
        };
        Ok(Self {
            w,
            payer,
            bridge: crate::lez::bridge_program_id(),
            attest: AccountId::new(consumers::ATTEST_PROGRAM),
        })
    }

    pub fn catalog(&self) -> ProgramCatalog {
        ProgramCatalog::from([
            (
                self.attest,
                Program::new(program_methods::ATTEST_ELF.into()).unwrap(),
            ),
            (
                self.bridge,
                Program::new(program_methods::BRIDGE_ELF.into()).unwrap(),
            ),
        ])
    }

    /// Immutable deploy at `header` (whose key must be in the wallet).
    pub async fn deploy(&mut self, header: AccountId, elf: &[u8]) -> Result<()> {
        let user_elf = risc0_binfmt::ProgramBinary::decode(elf)
            .map_err(ef)?
            .user_elf;
        let segs: Vec<AccountId> =
            std::iter::repeat_with(|| self.w.create_new_account_public(None).0)
                .take(user_elf.len().div_ceil(MAX_SEGMENT_DATA_LEN))
                .collect();
        self.w.store_persistent_data().map_err(ef)?;
        ProgramLoader(&mut self.w)
            .deploy(header, &segs, elf.to_vec(), true, Some(self.payer))
            .await
            .map_err(ef)?;
        Ok(())
    }

    pub async fn deployed(&mut self, header: AccountId) -> Result<bool> {
        Ok(ProgramLoader(&mut self.w)
            .program(header)
            .await
            .map_err(ef)?
            .is_some())
    }

    pub async fn state(&self, a: Actor) -> Result<Vec<u8>> {
        Ok(self
            .w
            .get_account_view(a)
            .await
            .map_err(ef)?
            .map(|acc| acc.data.actor_state(a.program_account_id).to_vec())
            .unwrap_or_default())
    }

    pub async fn pda_state(&self, program: AccountId, seed: [u8; 32]) -> Result<Vec<u8>> {
        self.state(Actor::new(
            AccountId::for_public_pda(&program, &PdaSeed::new(seed)),
            program,
        ))
        .await
    }

    /// Signed, fee-paying public tx from `signer` (a wallet public account; fees from `self.payer`
    /// when it signs too). `new_pdas` = admission evidence for PDAs it may create.
    pub async fn public(
        &self,
        signer: AccountId,
        to: Actor,
        mut actors: Vec<Actor>,
        new_pdas: &[(AccountId, [u8; 32])],
        msg: &impl BorshSerialize,
        gas: u64,
    ) -> Result<LezTx> {
        actors.push(to);
        let key = self
            .w
            .get_account_public_signing_key(signer)
            .ok_or_else(|| anyhow!("no key for {signer} in the wallet"))?
            .clone();
        let nonce = self
            .w
            .get_account_view(Actor::native_balance(signer))
            .await
            .map_err(ef)?
            .unwrap_or_default()
            .nonce;
        let mut m =
            Message::try_new(to, actors, BTreeMap::from([(signer, nonce)]), msg).map_err(ef)?;
        m.admission_evidence = new_pdas
            .iter()
            .map(|(program, seed)| PublicAccountEvidence::Pda {
                program: *program,
                seed: PdaSeed::new(*seed),
            })
            .collect();
        m.fee = Some(lee::FeeDeclaration::new(
            signer,
            gas,
            0,
            wallet::max_fee_for(gas),
        ));
        let tx = LeeTransaction::Public(PublicTransaction::new(
            m.clone(),
            WitnessSet::for_message(&m, &[&key]),
        ));
        let hash = self
            .w
            .client_owned()
            .send_transaction(tx)
            .await
            .map_err(ef)?;
        self.included(hash).await
    }

    /// Privacy-preserving root call `msg` to `mentions[0]` (a holder's private account), with sealed
    /// async messages for `seals` (private recipients).
    pub async fn private(
        &mut self,
        mentions: Vec<AccountMention>,
        msg: Vec<u8>,
        seals: Vec<AccountMention>,
    ) -> Result<LezTx> {
        self.w.sync_to_latest_block().await.map_err(ef)?;
        let (declared, delivery) = self.w.async_destinations(vec![], seals).map_err(ef)?;
        let mut accounts = mentions;
        accounts.extend(declared);
        let (hash, _) = self
            .w
            .send_tx(accounts, 0, msg, &self.catalog(), None, delivery)
            .await
            .map_err(ef)?;
        let r = self.included(hash).await?;
        self.w.sync_to_latest_block().await.map_err(ef)?;
        self.w.store_persistent_data().map_err(ef)?;
        Ok(r)
    }

    /// Unreceived pending messages of this wallet sent by the bridge program to a private account.
    pub async fn pending_bridge(&mut self) -> Result<Vec<PendingMessage>> {
        let bridge = self.bridge;
        Ok(self
            .w
            .owned_pending_messages()
            .await
            .map_err(ef)?
            .into_iter()
            .filter(|p| p.body.to.program_account_id == bridge)
            .collect())
    }

    /// Second tx of a private credit: `holder` applies the pending `Credit` (authorized).
    pub async fn receive(&mut self, holder: AccountId, p: PendingMessage) -> Result<LezTx> {
        let me = AccountIdentity::PrivateOwned(holder).select_program_actor_state(self.bridge);
        let catalog = self.catalog();
        let (hash, _) = self
            .w
            .receive_pending_message_with(p, vec![me], &catalog, None, AsyncDelivery::default())
            .await
            .map_err(ef)?;
        let r = self.included(hash).await?;
        self.w.sync_to_latest_block().await.map_err(ef)?;
        self.w.store_persistent_data().map_err(ef)?;
        Ok(r)
    }

    async fn included(&self, hash: common::HashType) -> Result<LezTx> {
        let (tx, block_id) = self.w.poll_transaction(hash).await.map_err(ef)?;
        let block = self
            .w
            .get_block(block_id)
            .await
            .map_err(ef)?
            .ok_or_else(|| anyhow!("block {block_id} missing"))?;
        let pos = block
            .body
            .transactions
            .iter()
            .position(|t| *t == tx)
            .ok_or_else(|| anyhow!("tx {hash} not in block {block_id}"))?;
        Ok(LezTx {
            hash: hash.to_string(),
            block: block_id,
            ok: !block.body.is_reverted(pos),
            bytes: borsh::to_vec(&tx)?,
            public_actors: public_actors(&tx),
        })
    }

    pub async fn head(&self) -> Result<u64> {
        self.w.get_last_block_id().await.map_err(ef)
    }

    pub async fn block_hash(&self, id: u64) -> Result<[u8; 32]> {
        Ok(self
            .w
            .get_block(id)
            .await
            .map_err(ef)?
            .ok_or_else(|| anyhow!("no block {id}"))?
            .header
            .hash
            .0)
    }

    /// Last block in `from..=to` with a non-reverted tx naming `actor` (account + owning program)
    /// as a public actor, scanning back from `to` (the write is usually recent).
    pub async fn last_write(&self, actor: Actor, from: u64, to: u64) -> Result<Option<u64>> {
        for id in (from..=to).rev() {
            let Some(b) = self.w.get_block(id).await.map_err(ef)? else {
                bail!("no block {id}");
            };
            let txs: Vec<(bool, Vec<Actor>)> = b
                .body
                .transactions
                .iter()
                .enumerate()
                .map(|(pos, t)| (b.body.is_reverted(pos), public_actors(t)))
                .collect();
            if names_live(&txs, &actor) {
                return Ok(Some(id));
            }
        }
        Ok(None)
    }

    /// Recovery of a wiped wallet from its mnemonic alone: fresh storage at `home`, key trees
    /// regenerated from the phrase, every block rescanned for the accounts' notes.
    pub async fn restore_at(
        home: &std::path::Path,
        phrase: &str,
        payer: AccountId,
    ) -> Result<Self> {
        let m: bip39::Mnemonic = phrase.trim().parse().map_err(ef)?;
        let (mut w, _) = WalletCore::new_init_storage(
            home.join("wallet_config.json"),
            home.join("storage.json"),
            None,
            "",
        )
        .map_err(ef)?;
        w.restore_storage(&m);
        // depth 1 = the root nodes, where the bridge holder and its funding account live
        w.restore_keys(1).await.map_err(ef)?;
        w.store_persistent_data().map_err(ef)?;
        Self::open_at(home, payer)
    }

    pub fn holder(&self) -> Result<WalletHolder> {
        wallet_holder(self.w.storage().key_chain())
    }
}

pub fn public_actors(tx: &LeeTransaction) -> Vec<Actor> {
    match tx {
        LeeTransaction::Public(p) => p.message.public_context.actors.iter().copied().collect(),
        LeeTransaction::PrivacyPreserving(p) => {
            p.message.public_context.actors.iter().copied().collect()
        }
    }
}

/// `bridge_program_id` = account of the image-derived deploy key.
pub fn bridge_program_id() -> AccountId {
    key_account(bridge::host::deploy_key(program_methods::BRIDGE_ID))
}

pub fn key_account(k: [u8; 32]) -> AccountId {
    AccountId::from(&lee::PublicKey::new_from_private_key(
        &lee::PrivateKey::try_new(k).unwrap(),
    ))
}
