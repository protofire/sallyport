//! Borrowed (zero-copy) borsh decoding of the large request messages (gas, docs/DECISIONS.md
//! D-GAS-3): byte vectors become slices of the message instead of fresh `Vec`s. Accepts exactly
//! the bytes `borsh::from_slice` accepts for the owned type (same layout, tags, no trailing bytes).

use crate::{AttestRequest, Proof};
use borsh::BorshDeserialize;
use inclusion::{Account, Fact, Locator, Pred};

/// Cursor over borsh bytes.
pub struct Cur<'a>(pub &'a [u8]);

impl<'a> Cur<'a> {
    pub fn u8(&mut self) -> Option<u8> {
        let (b, r) = self.0.split_first()?;
        self.0 = r;
        Some(*b)
    }

    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (b, r) = self.0.split_at_checked(n)?;
        self.0 = r;
        Some(b)
    }

    pub fn arr<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    pub fn len(&mut self) -> Option<usize> {
        Some(u32::from_le_bytes(self.arr()?) as usize)
    }

    /// borsh `Vec<u8>`.
    pub fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = self.len()?;
        self.take(n)
    }

    /// borsh `Vec<Vec<u8>>` (no preallocation from the untrusted count).
    pub fn vecs(&mut self) -> Option<Vec<&'a [u8]>> {
        let n = self.len()?;
        let mut v = Vec::new();
        for _ in 0..n {
            v.push(self.bytes()?);
        }
        Some(v)
    }

    /// Any owned borsh value (used for the small fields).
    pub fn get<T: BorshDeserialize>(&mut self) -> Option<T> {
        T::deserialize(&mut self.0).ok()
    }

    pub fn end(&self) -> Option<()> {
        self.0.is_empty().then_some(())
    }
}

/// [`Proof`] with borrowed byte vectors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofRef<'a> {
    Account {
        account: Account,
        account_proof: Vec<&'a [u8]>,
    },
    Storage {
        account: Account,
        account_proof: Vec<&'a [u8]>,
        value: [u8; 32],
        storage_proof: Vec<&'a [u8]>,
    },
    Log {
        receipt: &'a [u8],
        receipt_proof: Vec<&'a [u8]>,
    },
    LogCompact {
        receipt_proof: Vec<&'a [u8]>,
    },
}

/// [`AttestRequest`] with borrowed byte vectors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestRequestRef<'a> {
    pub instance_id: [u8; 32],
    pub exec_header_rlp: &'a [u8],
    pub ancestry: Vec<&'a [u8]>,
    pub locator: Locator,
    pub proof: ProofRef<'a>,
    pub preds: Vec<Pred>,
    pub ctx: &'a [u8],
}

impl<'a> AttestRequestRef<'a> {
    /// Decodes a whole borsh `AttestRequest`.
    pub fn decode(b: &'a [u8]) -> Option<Self> {
        let mut c = Cur(b);
        let r = Self::read(&mut c)?;
        c.end()?;
        Some(r)
    }

    fn read(c: &mut Cur<'a>) -> Option<Self> {
        Some(AttestRequestRef {
            instance_id: c.arr()?,
            exec_header_rlp: c.bytes()?,
            ancestry: c.vecs()?,
            locator: c.get()?,
            proof: match c.u8()? {
                0 => ProofRef::Account {
                    account: c.get()?,
                    account_proof: c.vecs()?,
                },
                1 => ProofRef::Storage {
                    account: c.get()?,
                    account_proof: c.vecs()?,
                    value: c.arr()?,
                    storage_proof: c.vecs()?,
                },
                2 => ProofRef::Log {
                    receipt: c.bytes()?,
                    receipt_proof: c.vecs()?,
                },
                3 => ProofRef::LogCompact {
                    receipt_proof: c.vecs()?,
                },
                _ => return None,
            },
            preds: c.get()?,
            ctx: c.bytes()?,
        })
    }
}

fn refs(v: &[Vec<u8>]) -> Vec<&[u8]> {
    v.iter().map(Vec::as_slice).collect()
}

impl AttestRequest {
    /// Borrowed view (for the shared [`crate::verify`] core).
    pub fn view(&self) -> AttestRequestRef<'_> {
        AttestRequestRef {
            instance_id: self.instance_id,
            exec_header_rlp: &self.exec_header_rlp,
            ancestry: refs(&self.ancestry),
            locator: self.locator.clone(),
            proof: match &self.proof {
                Proof::Account {
                    account,
                    account_proof,
                } => ProofRef::Account {
                    account: account.clone(),
                    account_proof: refs(account_proof),
                },
                Proof::Storage {
                    account,
                    account_proof,
                    value,
                    storage_proof,
                } => ProofRef::Storage {
                    account: account.clone(),
                    account_proof: refs(account_proof),
                    value: *value,
                    storage_proof: refs(storage_proof),
                },
                Proof::Log {
                    receipt,
                    receipt_proof,
                } => ProofRef::Log {
                    receipt,
                    receipt_proof: refs(receipt_proof),
                },
                Proof::LogCompact { receipt_proof } => ProofRef::LogCompact {
                    receipt_proof: refs(receipt_proof),
                },
            },
            preds: self.preds.clone(),
            ctx: &self.ctx,
        }
    }
}

/// [`crate::AttestReply`] for a consumer: the echoed predicates are validated as borsh but not
/// materialised (a consumer re-checks its own predicates on `fact`; D-GAS-5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestReplyRef<'a> {
    pub instance_id: [u8; 32],
    pub statement_id: [u8; 32],
    pub fact: Fact,
    pub ctx: &'a [u8],
}

impl<'a> AttestReplyRef<'a> {
    /// Decodes a whole borsh `AttestReply`; `None` iff `borsh::from_slice::<AttestReply>` fails.
    pub fn decode(b: &'a [u8]) -> Option<Self> {
        let mut c = Cur(b);
        let instance_id = c.arr()?;
        let statement_id = c.arr()?;
        let fact = c.get()?;
        for _ in 0..c.len()? {
            skip_pred(&mut c)?;
        }
        let ctx = c.bytes()?;
        c.end()?;
        Some(AttestReplyRef {
            instance_id,
            statement_id,
            fact,
            ctx,
        })
    }
}

/// Skips one borsh [`Pred`] with the derive's checks: variant < 6, `FieldSel` variant < 9 with
/// its payload (`LogTopic(u8)` = 6, `LogDataWord(u32)` = 7), then the `Vec<u8>` value.
fn skip_pred(c: &mut Cur) -> Option<()> {
    if c.u8()? > 5 {
        return None;
    }
    match c.u8()? {
        0..=5 | 8 => {}
        6 => {
            c.take(1)?;
        }
        7 => {
            c.take(4)?;
        }
        _ => return None,
    }
    c.bytes().map(|_| ())
}

/// Borsh variant index of [`crate::Msg::Attest`].
pub const MSG_ATTEST: u8 = 3;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Msg;

    fn sample(proof: Proof) -> AttestRequest {
        AttestRequest {
            instance_id: [7; 32],
            exec_header_rlp: vec![1, 2, 3],
            ancestry: vec![vec![4; 5], vec![]],
            locator: Locator::Storage {
                address: [9; 20],
                slot: [8; 32],
            },
            proof,
            preds: inclusion::erc20_transfer_preds([1; 20], None, Some([2; 20]), Some([3; 32])),
            ctx: vec![5; 3],
        }
    }

    #[test]
    fn view_decode_matches_borsh() {
        let a = Account::empty();
        for p in [
            Proof::Account {
                account: a.clone(),
                account_proof: vec![vec![1; 40], vec![2; 3]],
            },
            Proof::Storage {
                account: a.clone(),
                account_proof: vec![vec![1; 40]],
                value: [6; 32],
                storage_proof: vec![],
            },
            Proof::Log {
                receipt: vec![0xc0; 70],
                receipt_proof: vec![vec![3; 33]],
            },
            Proof::LogCompact {
                receipt_proof: vec![vec![3; 33], vec![4; 2]],
            },
        ] {
            let req = sample(p);
            let b = borsh::to_vec(&req).unwrap();
            assert_eq!(AttestRequestRef::decode(&b), Some(req.view()));
            // every truncation and any trailing byte is rejected, as by borsh
            for n in 0..b.len() {
                assert_eq!(AttestRequestRef::decode(&b[..n]), None, "len {n}");
                assert!(borsh::from_slice::<AttestRequest>(&b[..n]).is_err());
            }
            let mut t = b.clone();
            t.push(0);
            assert_eq!(AttestRequestRef::decode(&t), None);
            let m = borsh::to_vec(&Msg::Attest(req)).unwrap();
            assert_eq!(m[0], MSG_ATTEST);
            assert_eq!(m[1..], b[..]);
        }
        // reply view: same acceptance as borsh, over every truncation and byte flip
        let req = sample(Proof::Log {
            receipt: vec![],
            receipt_proof: vec![],
        });
        let fact = Fact {
            chain_id: 1,
            genesis_validators_root: [2; 32],
            execution_block_hash: [3; 32],
            block_number: 4,
            locator: req.locator.clone(),
            value: inclusion::FactValue::Slot([5; 32]),
        };
        let mut preds = req.preds.clone();
        preds.push(Pred::Lt {
            field: inclusion::FieldSel::LogTopic(2),
            value: vec![1],
        });
        let reply = crate::AttestReply {
            instance_id: [1; 32],
            statement: inclusion::Statement {
                id: [9; 32],
                fact: fact.clone(),
                preds,
            },
            ctx: vec![4; 7],
        };
        let b = borsh::to_vec(&reply).unwrap();
        assert_eq!(
            AttestReplyRef::decode(&b),
            Some(AttestReplyRef {
                instance_id: [1; 32],
                statement_id: [9; 32],
                fact,
                ctx: &[4; 7],
            })
        );
        for n in 0..=b.len() {
            assert_eq!(
                AttestReplyRef::decode(&b[..n]).is_some(),
                borsh::from_slice::<crate::AttestReply>(&b[..n]).is_ok()
            );
        }
        for i in 0..b.len() {
            for v in [0u8, 1, 2, 5, 6, 7, 8, 9, 0x80, 0xff] {
                let mut t = b.clone();
                t[i] = v;
                assert_eq!(
                    AttestReplyRef::decode(&t).is_some(),
                    borsh::from_slice::<crate::AttestReply>(&t).is_ok(),
                    "byte {i} = {v}"
                );
            }
        }
        // unknown proof tag
        let mut b = borsh::to_vec(&sample(Proof::Log {
            receipt: vec![],
            receipt_proof: vec![],
        }))
        .unwrap();
        let tag = 32 + 4 + 3 + 4 + 4 + 5 + 4 + 1 + 20 + 32;
        assert_eq!(b[tag], 2);
        b[tag] = 3;
        assert_eq!(AttestRequestRef::decode(&b), None);
    }
}
