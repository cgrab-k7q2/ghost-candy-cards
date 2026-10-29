//! End-to-end tests of the template in the Ootle engine test harness.
use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT as G, scalar::Scalar};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use tari_ootle_common_types::substate_type::SubstateType;
use tari_template_lib::prelude::tari_bor;
use tari_ootle_transaction::{Epoch, Transaction, args};
use tari_template_lib::types::{
    Amount,
    ComponentAddress,
    amount,
    crypto::{RistrettoPublicKeyBytes, Scalar32Bytes},
    stealth::StealthTransferStatement,
};
use tari_template_test_tooling::{TemplateTest, support::stealth, support::stealth::NO_INPUTS};

const TREAT: Amount = amount!(3);

struct Card {
    s: Scalar,
    p: RistrettoPublicKeyBytes,
}

fn new_card() -> Card {
    let s = Scalar::random(&mut OsRng);
    let p = RistrettoPublicKeyBytes::from_bytes((s * G).compress().as_bytes()).unwrap();
    Card { s, p }
}

fn challenge(component: &ComponentAddress, card: &RistrettoPublicKeyBytes, r: &RistrettoPublicKeyBytes, t: &StealthTransferStatement) -> Scalar {
    let outputs = tari_bor::encode(&t.outputs_statement).unwrap();
    let mut h = Sha256::new();
    h.update(b"ghost-candy-cards/v1");
    h.update(component.as_bytes());
    h.update(card.as_bytes());
    h.update(r.as_bytes());
    h.update(&outputs);
    let mut e: [u8; 32] = h.finalize().into();
    e[31] &= 0x0f;
    Option::from(Scalar::from_canonical_bytes(e)).unwrap()
}

/// Schnorr proof of the card secret, bound to `transfer`'s outputs.
fn prove(component: &ComponentAddress, card: &Card, t: &StealthTransferStatement) -> (RistrettoPublicKeyBytes, Scalar32Bytes) {
    let r = Scalar::random(&mut OsRng);
    let big_r = RistrettoPublicKeyBytes::from_bytes((r * G).compress().as_bytes()).unwrap();
    let e = challenge(component, &card.p, &big_r, t);
    let z = r + e * card.s;
    (big_r, Scalar32Bytes::from(z.to_bytes()))
}

fn treat_transfer() -> StealthTransferStatement {
    // Take TREAT revealed CANDY from the bowl, emit one blinded stealth output of TREAT.
    stealth::generate_transfer_data(NO_INPUTS, 3u64, Some(3u64), 0u64).statement
}

fn setup(cards: &[&Card], porch_light_off_epoch: u64) -> (TemplateTest, ComponentAddress) {
    let mut test = TemplateTest::new(env!("CARGO_MANIFEST_DIR"), ["."]);
    let template = test.get_template_address("GhostCandyCards");
    let points: Vec<RistrettoPublicKeyBytes> = cards.iter().map(|c| c.p).collect();
    test.execute_expect_success(
        Transaction::builder_localnet(Epoch(1))
            .call_function(template, "new", args![points, TREAT, porch_light_off_epoch])
            .build_and_seal(test.secret_key()),
        vec![],
    );
    let bowl = test.get_previous_output_address(SubstateType::Component).as_component_address().unwrap();
    (test, bowl)
}

fn claim(test: &mut TemplateTest, bowl: ComponentAddress, card: &RistrettoPublicKeyBytes, r: RistrettoPublicKeyBytes, z: Scalar32Bytes, t: StealthTransferStatement) -> Transaction {
    let _ = test;
    Transaction::builder_localnet(Epoch(1))
        .call_method(bowl, "trick_or_treat", args![*card, r, z, t])
        .build_and_seal(test.secret_key())
}

#[test]
fn honest_claim_pays_one_stealth_treat() {
    let (a, b) = (new_card(), new_card());
    let (mut test, bowl) = setup(&[&a, &b], 100);
    let t = treat_transfer();
    let (r, z) = prove(&bowl, &a, &t);
    let tx = claim(&mut test, bowl, &a.p, r, z, t);
    let result = test.execute_expect_success(tx, vec![]);
    let diff = result.finalize.any_accept().unwrap();
    let utxos: Vec<_> = diff.up_iter().filter_map(|(_, s)| s.substate_value().as_utxo()).collect();
    assert_eq!(utxos.len(), 1, "the treat is exactly one stealth UTXO");
    let left: u64 = test.call_method(bowl, "cards_left", args![], vec![]);
    assert_eq!(left, 1);
    let redeemed: bool = test.call_method(bowl, "is_redeemed", args![a.p], vec![]);
    assert!(redeemed);
    let bowl_left: Amount = test.call_method(bowl, "bowl_balance", args![], vec![]);
    assert_eq!(bowl_left, TREAT, "one treat left for card b");
}

#[test]
fn challenge_helper_matches_client() {
    let a = new_card();
    let (mut test, bowl) = setup(&[&a], 100);
    let t = treat_transfer();
    let r_scalar = Scalar::random(&mut OsRng);
    let r = RistrettoPublicKeyBytes::from_bytes((r_scalar * G).compress().as_bytes()).unwrap();
    let ours = challenge(&bowl, &a.p, &r, &t);
    let theirs: Scalar32Bytes = test.call_method(bowl, "claim_challenge", args![a.p, r, t], vec![]);
    assert_eq!(theirs.as_bytes(), ours.as_bytes());
}

#[test]
fn front_runner_cannot_reuse_proof_with_own_outputs() {
    let a = new_card();
    let (mut test, bowl) = setup(&[&a], 100);
    let honest = treat_transfer();
    let (r, z) = prove(&bowl, &a, &honest);
    // The watcher copies (P, R, z) but substitutes outputs paying themselves.
    let thief = treat_transfer();
    let tx = claim(&mut test, bowl, &a.p, r, z, thief);
    test.execute_expect_failure(tx, vec![]);
    // The honest claim still works afterwards.
    let tx = claim(&mut test, bowl, &a.p, r, z, honest);
    test.execute_expect_success(tx, vec![]);
}

#[test]
fn card_cannot_be_redeemed_twice() {
    let a = new_card();
    let (mut test, bowl) = setup(&[&a, &new_card()], 100);
    let t1 = treat_transfer();
    let (r1, z1) = prove(&bowl, &a, &t1);
    let tx = claim(&mut test, bowl, &a.p, r1, z1, t1);
    test.execute_expect_success(tx, vec![]);
    let t2 = treat_transfer();
    let (r2, z2) = prove(&bowl, &a, &t2);
    let tx = claim(&mut test, bowl, &a.p, r2, z2, t2);
    test.execute_expect_failure(tx, vec![]);
}

#[test]
fn unknown_card_and_wrong_secret_rejected() {
    let a = new_card();
    let (mut test, bowl) = setup(&[&a], 100);
    let stranger = new_card();
    let t = treat_transfer();
    let (r, z) = prove(&bowl, &stranger, &t);
    let tx = claim(&mut test, bowl, &stranger.p, r, z, t);
    test.execute_expect_failure(tx, vec![]);

    // Right card point, wrong secret.
    let forged = Card { s: Scalar::random(&mut OsRng), p: a.p };
    let t = treat_transfer();
    let (r, z) = prove(&bowl, &forged, &t);
    let tx = claim(&mut test, bowl, &a.p, r, z, t);
    test.execute_expect_failure(tx, vec![]);
}

#[test]
fn greedy_claim_rejected() {
    let a = new_card();
    let (mut test, bowl) = setup(&[&a, &new_card()], 100);
    // Try to take two treats with one card.
    let t = stealth::generate_transfer_data(NO_INPUTS, 6u64, Some(6u64), 0u64).statement;
    let (r, z) = prove(&bowl, &a, &t);
    let tx = claim(&mut test, bowl, &a.p, r, z, t);
    test.execute_expect_failure(tx, vec![]);
}

#[test]
fn host_cannot_sweep_while_porch_light_is_on() {
    let a = new_card();
    let (mut test, bowl) = setup(&[&a], 100);
    let t = treat_transfer();
    let tx = Transaction::builder_localnet(Epoch(1))
        .call_method(bowl, "sweep", args![t])
        .build_and_seal(test.secret_key());
    test.execute_expect_failure(tx, vec![test.owner_proof()]);
}
