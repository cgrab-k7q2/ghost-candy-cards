//! # Ghost Candy Cards
//!
//! A host prints paper "candy cards". Each card carries one secret scalar `s`; the component only
//! stores the matching public point `P = s·G`. Whoever holds a card can redeem it once for a fixed
//! amount of CANDY, a *stealth* resource. The payout lands as a stealth UTXO, so the chain records
//! that *a* card was redeemed but not who received the candy: no account address, no linkable
//! output owner, and the memo is encrypted to the recipient.
//!
//! ## Why a Schnorr proof and not "reveal the secret"
//! Revealing `s` in a transaction would let anyone who sees it first copy `s` into their own claim
//! with their own outputs. Instead the claimant proves knowledge of `s` with a Schnorr signature
//! whose challenge commits to the exact stealth outputs of the claim:
//!
//! ```text
//! e = H("ghost-candy-cards/v1" || component || P || R || cbor(outputs_statement))   (top 4 bits cleared)
//! valid  <=>  z·G == R + e·P
//! ```
//!
//! Swapping in different outputs changes `e`, so a copied proof is useless. Each card point is
//! removed on first use, so a card cannot be spent twice. The verification runs on Ootle's native
//! Ristretto intrinsics (`ristretto_mul_base`, `ristretto_mul`, `ristretto_add`).
//!
//! `claim_challenge` is a read-only helper that returns `e` for a given `(P, R, statement)`. Clients
//! call it in a dry run, so they never have to reproduce the CBOR encoding themselves.

use sha2::{Digest, Sha256};
use tari_template_lib::prelude::*;

const DOMAIN: &[u8] = b"ghost-candy-cards/v1";

/// Hash the claim transcript into a canonical Ristretto scalar (< 2^252 < l).
fn challenge_scalar(
    component: &ComponentAddress,
    card: &RistrettoPublicKeyBytes,
    nonce_point: &RistrettoPublicKeyBytes,
    outputs_cbor: &[u8],
) -> Scalar32Bytes {
    let mut h = Sha256::new();
    h.update(DOMAIN);
    h.update(component.as_bytes());
    h.update(card.as_bytes());
    h.update(nonce_point.as_bytes());
    h.update(outputs_cbor);
    let mut e: [u8; 32] = h.finalize().into();
    // Little-endian scalar: clearing the top 4 bits keeps it below 2^252, hence canonical mod l.
    e[31] &= 0x0f;
    Scalar32Bytes::from(e)
}

#[template]
mod ghost_candy_cards {
    use super::*;

    pub struct GhostCandyCards {
        /// Unredeemed card points. A point is removed the moment its card is redeemed.
        unspent_cards: Vec<RistrettoPublicKeyBytes>,
        /// Card points already redeemed (public, so anyone can audit that each card paid once).
        spent_cards: Vec<RistrettoPublicKeyBytes>,
        /// Fixed treat per card, in CANDY base units.
        treat: Amount,
        /// The CANDY stealth resource.
        candy: ResourceManager,
        /// Revealed CANDY reserved for unredeemed cards.
        bowl: Vault,
        /// After this epoch the host may sweep leftover candy (porch light off).
        porch_light_off_epoch: u64,
        /// The host, who may sweep after the deadline.
        host: RistrettoPublicKeyBytes,
    }

    impl GhostCandyCards {
        /// Create a bowl with one card per point in `cards`, each worth `treat` CANDY.
        /// The full supply (`cards.len() * treat`) is minted into the bowl, so every card is fully backed.
        pub fn new(cards: Vec<RistrettoPublicKeyBytes>, treat: Amount, porch_light_off_epoch: u64) -> Component<Self> {
            assert!(!cards.is_empty(), "A bowl needs at least one card");
            assert!(treat.is_positive(), "A treat must be worth something");
            let mut seen: Vec<RistrettoPublicKeyBytes> = Vec::with_capacity(cards.len());
            for c in &cards {
                assert!(!c.is_zero(), "Card point must not be the identity");
                assert!(!seen.contains(c), "Duplicate card point");
                seen.push(*c);
            }
            let supply = treat * Amount::from(cards.len() as u64);
            let host = CallerContext::transaction_signer_public_key();

            let bucket = ResourceBuilder::stealth()
                .with_token_symbol("CANDY")
                .with_divisibility(0)
                .initial_supply(supply);
            let candy: ResourceManager = bucket.resource_address().into();

            emit_event("ghost_candy.bowl_filled", metadata! {
                "cards" => cards.len().to_string(),
                "treat" => treat.to_string(),
                "porch_light_off_epoch" => porch_light_off_epoch.to_string(),
            });

            Component::new(Self {
                unspent_cards: cards,
                spent_cards: Vec::new(),
                treat,
                candy,
                bowl: Vault::from_bucket(bucket),
                porch_light_off_epoch,
                host,
            })
            .with_access_rules(
                AccessRules::new()
                    .add_method_rule("sweep", rule!(public_key(host)))
                    .default(rule!(allow_all)),
            )
            .create()
        }

        /// Returns the Schnorr challenge for a claim. Call in a dry run, then sign: `z = r + e·s`.
        pub fn claim_challenge(
            &self,
            card: RistrettoPublicKeyBytes,
            nonce_point: RistrettoPublicKeyBytes,
            transfer: StealthTransferStatement,
        ) -> Scalar32Bytes {
            let outputs = tari_bor::encode(&transfer.outputs_statement).expect("encode outputs statement");
            challenge_scalar(&CallerContext::current_component_address(), &card, &nonce_point, &outputs)
        }

        /// Redeem one card. `transfer` must take exactly `treat` revealed CANDY as input and send it to
        /// stealth outputs of the claimant's choosing. `(nonce_point, response)` is a Schnorr proof of the
        /// card secret bound to those outputs.
        pub fn trick_or_treat(
            &mut self,
            card: RistrettoPublicKeyBytes,
            nonce_point: RistrettoPublicKeyBytes,
            response: Scalar32Bytes,
            transfer: StealthTransferStatement,
        ) {
            let idx = match self.unspent_cards.iter().position(|c| *c == card) {
                Some(i) => i,
                None => {
                    if self.spent_cards.contains(&card) {
                        panic!("Boo! This card was already redeemed");
                    }
                    panic!("Unknown card");
                },
            };
            assert_eq!(
                transfer.inputs_statement.revealed_amount, self.treat,
                "A card is worth exactly one treat"
            );

            let outputs = tari_bor::encode(&transfer.outputs_statement).expect("encode outputs statement");
            let e = challenge_scalar(&CallerContext::current_component_address(), &card, &nonce_point, &outputs);
            let lhs = intrinsics::ristretto_mul_base(&response);
            let rhs = intrinsics::ristretto_add(&nonce_point, &intrinsics::ristretto_mul(&card, &e));
            assert!(lhs == rhs, "Invalid card proof");

            // Spend the card before moving funds (no double redemption, even within one transaction).
            self.unspent_cards.swap_remove(idx);
            self.spent_cards.push(card);

            let input = self.bowl.withdraw(self.treat);
            if let Some(change) = self.candy.stealth_transfer_with_opt_input_bucket(transfer, Some(input)) {
                // Any revealed output goes back into the bowl; the claimant's candy stays stealth.
                self.bowl.deposit(change);
            }
            emit_event("ghost_candy.treat", metadata! {
                "cards_left" => self.unspent_cards.len().to_string(),
            });
        }

        /// After the porch light goes off, the host can take back candy for unredeemed cards as stealth
        /// outputs of their own. Before that, nobody can touch the bowl except card holders.
        pub fn sweep(&mut self, transfer: StealthTransferStatement) {
            assert!(
                Consensus::current_epoch() > self.porch_light_off_epoch,
                "Porch light is still on: cards can still be redeemed"
            );
            let left = self.bowl.balance();
            assert_eq!(transfer.inputs_statement.revealed_amount, left, "Sweep must take the whole bowl");
            let input = self.bowl.withdraw(left);
            if let Some(change) = self.candy.stealth_transfer_with_opt_input_bucket(transfer, Some(input)) {
                self.bowl.deposit(change);
            }
            self.unspent_cards.clear();
        }

        pub fn cards_left(&self) -> u64 {
            self.unspent_cards.len() as u64
        }

        pub fn is_redeemed(&self, card: RistrettoPublicKeyBytes) -> bool {
            self.spent_cards.contains(&card)
        }

        pub fn treat(&self) -> Amount {
            self.treat
        }

        pub fn candy_resource(&self) -> ResourceAddress {
            self.candy.resource_address()
        }

        pub fn bowl_balance(&self) -> Amount {
            self.bowl.balance()
        }

        pub fn porch_light_off_epoch(&self) -> u64 {
            self.porch_light_off_epoch
        }

        pub fn host(&self) -> RistrettoPublicKeyBytes {
            self.host
        }
    }
}
