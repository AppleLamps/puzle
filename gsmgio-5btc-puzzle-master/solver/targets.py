"""Canonical prize-target definitions and the single acceptance gate.

Every audit in this package must gate candidate scalars through this module.
Before it existed the targets were copy-pasted into individual audits, which
produced two documented defects:

1. Only eight of roughly seventy audit modules ever tested Better Half's
   ``hash160``.  Every exhaustive Chain 4 certificate is therefore a
   Half-only certificate, because a ``hash160`` target admits no point-space
   meet-in-the-middle.
2. The generated verification report reused the labels ``Half`` and
   ``Better_Half`` for the two 32-byte halves of the Cosmic base-38 output.
   Those are solver-derived scalars, not the prize.  Their addresses are
   recorded here as :data:`NON_TARGETS` so the confusion cannot recur.

The two real targets are asymmetric and the asymmetry matters:

* Half has spent, so its uncompressed public key is on chain.  It supports an
  exact point gate, which is the cheapest and strongest oracle in the puzzle.
* Better Half has never spent, so no public point exists for it.  Candidates
  can only be gated by deriving ``hash160``.  A gate written against a public
  key rejects every correct Better Half candidate silently.

Run ``python -m solver.targets`` to execute :func:`self_check`, which
re-derives every constant from the Base58Check address text.
"""

from __future__ import annotations

import hashlib

from .secp256k1_verify import BASE58, N, base58check, hash160, scalar_multiply


# --- Half: the funded prize address, public key exposed by six spends. ---
HALF_ADDRESS = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
HALF_X = int("f4d1bbd91e65e2a019566a17574e97dae908b784b388891848007e4f55d5a464", 16)
HALF_Y = int("9c73d25fc5ed8fd7227cab0be4e576c0c6404db5aa546286563e4be12bf33559", 16)
HALF_PUBLIC_UNCOMPRESSED = b"\x04" + HALF_X.to_bytes(32, "big") + HALF_Y.to_bytes(32, "big")
HALF_PUBLIC_COMPRESSED = bytes([2 + (HALF_Y & 1)]) + HALF_X.to_bytes(32, "big")
HALF_H160 = bytes.fromhex("a9553269572a317e39f0f518cb87c1a0ee1dbae4")

# --- Better Half: funded, never spent, so hash160 is the only available gate. ---
BETTER_ADDRESS = "17ucy1K9ZUAaoY6JVtM932W9jUp5LXfyHa"
BETTER_H160 = bytes.fromhex("4bc468447fe1b048ad030a2f9a125478eabc4ed6")

# Backwards-compatible aliases.  Several audits import these names from
# ``prime_reinsertion_audit``; that module now re-exports them from here.
TARGET_X = HALF_X
TARGET_Y = HALF_Y
TARGET_ADDRESS = HALF_ADDRESS
TARGET_COMPRESSED = HALF_PUBLIC_COMPRESSED

# --- Explicitly not targets. ---
# The two 32-byte halves of the Cosmic base-38 output are reproducible solver
# derivations, not prize keys.  Both were published in public repositories, and
# both resulting addresses were swept to zero from 2026-04-12 onward.  Their
# on-chain activity is a consequence of publication and must never be cited as
# creator confirmation, nor may these addresses be used as acceptance gates.
NON_TARGETS = {
    "cosmic_base38[0:32]": {
        "scalar": "0423d9115a1dc756d5d08d2de880ab508bd4745fc97709f4fcb513f2cb8fcc35",
        "p2pkh_compressed": "1JG648yaB7Wp2dpUfcZoRSD4q35oq47vCu",
        "p2pkh_uncompressed": "15E3pcDDXSKhvi3CLVhRTHEgd8dbVKvSZg",
        "historical_label": "Half",
        "status": "solver-derived, published, swept to zero; not a prize address",
    },
    "cosmic_base38[32:64]": {
        "scalar": "48cc46e66bdd36b09ae344552f606a761f9d90681f20dfefe2b43db18b623971",
        "p2pkh_compressed": "145ZQ9siLrsXBKf465wjdyQYAP5dRwhRhQ",
        "p2pkh_uncompressed": "1FhbJnrdq1FmeiXrpTqnpQ8jvYV7naze96",
        "historical_label": "Better_Half",
        "status": "solver-derived, published, swept to zero; not a prize address",
    },
}


def base58check_decode(address: str) -> bytes:
    """Return the 21-byte version||payload of a Base58Check string."""
    value = 0
    for character in address:
        value = value * 58 + BASE58.index(character)
    leading = len(address) - len(address.lstrip("1"))
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    decoded = b"\x00" * leading + raw
    payload, checksum = decoded[:-4], decoded[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != checksum:
        raise ValueError(f"bad Base58Check checksum: {address}")
    return payload


def serializations(x: int, y: int) -> dict[str, bytes]:
    """Both standard P2PKH public-key encodings of one curve point."""
    return {
        "uncompressed": b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big"),
        "compressed": bytes([2 + (y & 1)]) + x.to_bytes(32, "big"),
    }


def address_for(public: bytes) -> str:
    return base58check(b"\x00" + hash160(public))


def gate_point(
    x: int,
    y: int,
    *,
    half_public: bytes = HALF_PUBLIC_UNCOMPRESSED,
    half_h160: bytes = HALF_H160,
    better_h160: bytes = BETTER_H160,
) -> dict[str, object] | None:
    """Return match detail for a curve point, or ``None`` when nothing matches.

    Both targets are tested, and Better Half is tested under both public-key
    serializations because its correct encoding is unknown.

    The target constants are overridable so that a caller can exercise this
    exact code path against a planted synthetic target.  Production callers
    must leave them at their defaults.
    """
    encodings = serializations(x, y)
    digests = {name: hash160(value) for name, value in encodings.items()}
    hits: dict[str, object] = {}
    if encodings["uncompressed"] == half_public:
        hits["half_exact_public_key"] = True
    half_forms = [name for name, value in digests.items() if value == half_h160]
    better_forms = [name for name, value in digests.items() if value == better_h160]
    if half_forms:
        hits["half_hash160"] = half_forms
    if better_forms:
        hits["better_hash160"] = better_forms
    if not hits:
        return None
    hits["addresses"] = {name: address_for(value) for name, value in encodings.items()}
    return hits


def _public_point(scalar: int) -> tuple[int, int]:
    """Scalar multiplication, preferring libsecp256k1 when it is installed.

    The pure-Python fallback is correct but roughly three orders of magnitude
    slower, which matters only for bulk sweeps such as
    :mod:`solver.universal_regate`.
    """
    try:
        from coincurve import PrivateKey
    except ImportError:  # pragma: no cover - exercised only without coincurve
        return scalar_multiply(scalar)
    encoded = PrivateKey(scalar.to_bytes(32, "big")).public_key.format(compressed=False)
    return int.from_bytes(encoded[1:33], "big"), int.from_bytes(encoded[33:], "big")


def gate_scalar(scalar: int) -> dict[str, object] | None:
    """Gate one private scalar against both prize targets.

    Returns ``None`` for out-of-range scalars and for every non-match, so a
    caller can treat any truthy return as an accepted candidate.
    """
    reduced = scalar % N
    if reduced == 0:
        return None
    x, y = _public_point(reduced)
    result = gate_point(x, y)
    if result is not None:
        result["scalar"] = f"{reduced:064x}"
    return result


def gate_scalar_bytes(value: bytes) -> dict[str, object] | None:
    """Gate a 32-byte candidate."""
    if len(value) != 32:
        raise ValueError("prize scalars are 32 bytes wide")
    return gate_scalar(int.from_bytes(value, "big"))


def self_check() -> dict[str, object]:
    """Re-derive every constant from its address text and public key bytes."""
    half_payload = base58check_decode(HALF_ADDRESS)
    better_payload = base58check_decode(BETTER_ADDRESS)
    if half_payload[:1] != b"\x00" or better_payload[:1] != b"\x00":
        raise ValueError("both prize targets must be mainnet P2PKH")
    if half_payload[1:] != HALF_H160:
        raise ValueError("Half hash160 does not match its address")
    if better_payload[1:] != BETTER_H160:
        raise ValueError("Better Half hash160 does not match its address")
    if hash160(HALF_PUBLIC_UNCOMPRESSED) != HALF_H160:
        raise ValueError("Half public key does not hash to Half's address")
    if pow(HALF_Y, 2, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F) != (
        pow(HALF_X, 3, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F) + 7
    ) % 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F:
        raise ValueError("Half public point is not on secp256k1")

    # The non-targets must still reproduce their recorded addresses, so that a
    # future edit cannot quietly turn one of them back into a gate.
    for label, record in NON_TARGETS.items():
        scalar = int(record["scalar"], 16)
        x, y = scalar_multiply(scalar)
        encodings = serializations(x, y)
        if address_for(encodings["compressed"]) != record["p2pkh_compressed"]:
            raise ValueError(f"{label} compressed address drifted")
        if address_for(encodings["uncompressed"]) != record["p2pkh_uncompressed"]:
            raise ValueError(f"{label} uncompressed address drifted")
        if gate_scalar(scalar) is not None:
            raise ValueError(f"{label} must never satisfy a prize gate")

    return {
        "half": {
            "address": HALF_ADDRESS,
            "hash160": HALF_H160.hex(),
            "public_key_uncompressed": HALF_PUBLIC_UNCOMPRESSED.hex(),
            "gate": "exact public key, plus hash160 under both serializations",
        },
        "better_half": {
            "address": BETTER_ADDRESS,
            "hash160": BETTER_H160.hex(),
            "public_key_uncompressed": None,
            "gate": "hash160 only; never spent, so no public point exists",
        },
        "non_targets": NON_TARGETS,
    }


if __name__ == "__main__":  # pragma: no cover
    import json

    print(json.dumps(self_check(), indent=2))
