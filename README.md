# Ghost Candy Cards

Printable, one-time candy cards for Halloween. They pay out privately on Tari Ootle.

A host prints a sheet of paper cards. Each card has a QR code with one secret. The host deploys a
**bowl** (a Tari Ootle component) filled with `CANDY`, which is a *stealth* resource. The bowl stores
only each card's public point. Anyone who scans a card can redeem it **once** for one treat. The
treat lands as a **stealth UTXO**, so the chain shows that *a* card was redeemed, but not who
redeemed it or where the candy went.

Built for the Tari *Spooky Secrets* October build contest.

![demo card sheet](printer/demo-sheet.png)

## Why it is interesting

* **Bearer value on paper, without bearer-key risk.** A card is like a paper gift card, but the
  secret never appears on chain. The claimant proves they know it with a Schnorr proof.
* **Front-running-proof.** The proof's challenge commits to the exact stealth outputs of the claim:

  ```text
  e = SHA256("ghost-candy-cards/v1" || component || P || R || cbor(outputs_statement)), top 4 bits cleared
  valid  <=>  z·G == R + e·P
  ```

  If someone copies the proof from the mempool and swaps in their own outputs, `e` changes and the
  proof fails. A proof is also bound to one bowl, so it cannot be replayed on another bowl.
* **Private payouts.** The payout goes through `stealth_transfer_with_opt_input_bucket`. The
  claimant gets commitments plus an encrypted memo, not a public balance.
* **Native crypto.** Verification uses Ootle's Ristretto intrinsics (`ristretto_mul_base`,
  `ristretto_mul`, `ristretto_add`). There is no custom curve code in WASM.
* **Honest host rules.** The host can `sweep` leftover candy only after `porch_light_off_epoch`.
  Before then, only card holders can take candy from the bowl.

## Layout

| Path | What |
|---|---|
| `template/` | The Ootle template (`GhostCandyCards`) and its engine tests |
| `cli/` | `candy-cli`: makes cards, nonces and responses, verifies proofs, recomputes the challenge, runs a self-test |
| `printer/print_cards.py` | Turns card secrets into a printable SVG sheet of QR cards (`ghostcandy:<secret>`) |

## Template API

| Function | Purpose |
|---|---|
| `new(cards, treat, porch_light_off_epoch)` | Mints `cards × treat` stealth CANDY into the bowl |
| `claim_challenge(card, R, transfer)` | Read-only. Returns `e` so clients never re-implement the CBOR encoding |
| `trick_or_treat(card, R, z, transfer)` | Checks the proof, marks the card as spent, pays one treat to the claimant's stealth outputs |
| `sweep(transfer)` | Host only, and only after the porch light goes off. Takes back what is left |
| `cards_left`, `is_redeemed`, `treat`, `candy_resource`, `bowl_balance`, `porch_light_off_epoch`, `host` | Getters |

## Claim flow

1. Scan the card to get the secret `s`, and compute `P = s·G`.
2. The wallet builds a stealth transfer statement for `treat` CANDY to its own outputs
   (`accounts.create_stealth_transfer_statement`, input `FromBucket{revealed_amount: treat}`).
3. `candy-cli nonce` gives `r, R`. Dry-run `claim_challenge(P, R, statement)` to get `e`.
4. `candy-cli respond <e> <r> <s>` gives `z`. Submit `trick_or_treat(P, R, z, statement)`.

## Run it

```bash
# template + engine tests (Tari Ootle engine harness)
cd template && tari build && cargo test --release

# CLI + crypto self-test
cd cli && cargo run --release -- selftest

# print a card sheet
python3 printer/print_cards.py cards.txt sheet.svg points.json   # cards.txt: "<secret> <point>" per line
```

Test results (7/7 pass):

```
honest_claim_pays_one_stealth_treat ............ ok
challenge_helper_matches_client ................ ok
front_runner_cannot_reuse_proof_with_own_outputs ok
card_cannot_be_redeemed_twice .................. ok
unknown_card_and_wrong_secret_rejected ......... ok
greedy_claim_rejected .......................... ok
host_cannot_sweep_while_porch_light_is_on ...... ok
```

## Honest limits

* The card list (public points) is stored on chain, so the number of cards and when each one is
  redeemed are public. *Who* got the candy is not.
* Whoever physically holds a card owns it. A photographed card is a spent card, the same as cash.
* The demo sheet in `printer/` uses throwaway **demo** secrets, for testnet only. Never fund a bowl
  with them.
* Built against `tari_template_lib 0.36` and test tooling 0.48 (Esmeralda testnet). This is not audited.

## Credits

Written by an autonomous AI agent (coin grabber, `cgrab-k7q2`). MIT licensed.
