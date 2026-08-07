# Prize targets (on-chain facts)

These addresses held puzzle funds. Verify current balances and transaction history
on a block explorer independently.

## Half

| field | value |
| --- | --- |
| P2PKH address | `1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe` |
| hash160 | `a9553269572a317e39f0f518cb87c1a0ee1dbae4` |
| Uncompressed public key (from spends) | `04f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a4649c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559` |

Half has **spent**; the exact uncompressed public key above is on chain.

## Better Half

| field | value |
| --- | --- |
| P2PKH address | `17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa` |
| hash160 | `4bc468447fe1b048ad030a2f9a125478eabc4ed6` |
| Public key | **unknown** — this address has never spent |

## Acceptance gate for a candidate private key

A 32-byte secp256k1 scalar `k` (1 ≤ k < n) is a prize match if:

- **Half:** the derived public point's **uncompressed** encoding equals Half's
  public key above, **or** `hash160(public)` equals Half's hash160 under either
  standard serialization.
- **Better Half:** `hash160(public)` equals Better Half's hash160 under **either**
  compressed or uncompressed serialization (correct encoding is unknown).

Reproduce gate logic:

```bash
cd ../gsmgio-5btc-puzzle-master
python3 -m solver.targets
```

## Addresses that are not prize targets

Two addresses derived from later solver work on a "Cosmic" blob were published
publicly and swept to zero from 2026-04-12. Their on-chain activity reflects
publication, not creator confirmation. Do not treat them as acceptance gates:

- `1JG648yaB7Wp2dpUfcZoRSD4q35oq47vCu` / `15E3pcDDXSKhvi3CLVhRTHEgd8dbVKvSZg`
- `145ZQ9siLrsXBKf465wjdyQYAP5dRwhRhQ` / `1FhbJnrdq1FmeiXrpTqnpQ8jvYV7naze96`

## Checkerboard message (authenticated decrypt, not a target)

Phase 3.2 VIC checkerboard decode (149 digits) yields:

```text
INCASEYOUMANAGETOCRACKTHISTHEPRIVATEKEYSBELONGTOHALFANDBETTERHALFANDTHEYALSONEEDFUNDSTOLIVE
```

This names "Half" and "Better Half" in prose. It does not by itself define how
many private keys a solver must derive.
