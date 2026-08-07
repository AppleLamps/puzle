#!/usr/bin/env python3
"""Decrypt the phase 2, phase 3 and phase 3.2 payloads from the archived pages.

Chain, each step self-authenticating because the output is coherent English:

    phase2_keymaker.b64   password sha256("causality") as 64 ASCII hex chars
    phase3_riddles.b64    password = the seven-part phase 2 digest (64 hex chars)
    phase3.2 envelope     found inside the phase 3 plaintext, password
                          sha256("jacquefresco…principle") as 64 hex chars

Nothing here asserts that the passwords are *the intended* answers — it asserts
only that these passwords produce these plaintexts, which you can read.

Outputs go to `derived/`. Compare against `artifacts/` and the digest table in
`AUTHENTICATED_STAGES.md`.
"""

from __future__ import annotations

import hashlib

from _paths import CIPHERTEXTS, derived
from openssl_aes import find_envelopes, sha256_hex, try_digests, unarmour

# The seven-part phase 2 answer. Its SHA-256 is the phase 3 password; the digest
# is what is verifiable here, the seven strings are a community reconstruction
# that happens to hash to it.
PHASE2_SEVEN_PART_DIGEST = "1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5"

PHASE32_ANSWERS = "jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple"


def show(name: str, plain: bytes, digest: str) -> None:
    print(f"\n=== {name}  ({len(plain)} bytes, EVP digest {digest})")
    print(f"    sha256 {hashlib.sha256(plain).hexdigest()}")
    head = plain[:300].decode("utf-8", "replace").strip()
    print("    " + head.replace("\n", "\n    ")[:600])


def main() -> None:
    # --- phase 2 -----------------------------------------------------------
    blob = unarmour((CIPHERTEXTS / "phase2_keymaker.b64").read_text())
    hit = try_digests(blob, sha256_hex("causality"))
    if hit is None:
        raise SystemExit("phase 2 did not decrypt; re-run extract_ciphertexts.py")
    digest, phase2 = hit
    show("phase 2 (keymaker)", phase2, digest)
    derived("phase2_plaintext.txt").write_bytes(phase2)

    # --- phase 3 -----------------------------------------------------------
    blob = unarmour((CIPHERTEXTS / "phase3_riddles.b64").read_text())
    hit = try_digests(blob, PHASE2_SEVEN_PART_DIGEST.encode())
    if hit is None:
        raise SystemExit("phase 3 did not decrypt")
    digest, phase3 = hit
    show("phase 3 (riddles)", phase3, digest)
    derived("phase3_plaintext.txt").write_bytes(phase3)

    # --- phase 3.2 ---------------------------------------------------------
    # The phase 3.2 envelope is not on any archived page: it is carried inside
    # the phase 3 plaintext, so it only exists once the step above has run.
    envelopes = find_envelopes(phase3.decode("utf-8", "replace"))
    if not envelopes:
        raise SystemExit("no envelope inside the phase 3 plaintext")
    packed = envelopes[0]
    (CIPHERTEXTS / "phase32.b64").write_text(
        "\n".join(packed[i:i + 64] for i in range(0, len(packed), 64)) + "\n")
    print(f"\n    wrote ciphertexts/phase32.b64 ({len(unarmour(packed))} bytes) "
          "from inside the phase 3 plaintext")

    password = sha256_hex(PHASE32_ANSWERS)
    print(f"    phase 3.2 password = sha256({PHASE32_ANSWERS!r}) = {password.decode()}")
    hit = try_digests(unarmour(packed), password)
    if hit is None:
        raise SystemExit("phase 3.2 did not decrypt")
    digest, phase32 = hit
    show("phase 3.2 (Architect)", phase32, digest)
    derived("phase32_plaintext.bin").write_bytes(phase32)
    print("\n    wrote derived/phase32_plaintext.bin — feed it to phase32_classical.py")


if __name__ == "__main__":
    main()
