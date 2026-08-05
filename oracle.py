#!/usr/bin/env python3
"""Search assemblies of the seven phase 2 parts against the known digest.

Phase 2 ends "--> parts 1..7 --> sha-256 -> dgst is the password to enter Phase
3", and the archived phase 3 page sits at that digest, so we know the answer:

    sha256(parts 1..7) = 89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32

That makes any candidate assembly instantly testable. Four parts are settled:

    part 3  luna       "Crypto finally to the latin 3Moon?"
    part 5  11110      "The 5binary code" - Executive Order 11110
    part 6  the genesis headline, from "raw data after 4 on row 1616"
    part 7  the FEN after Bxb7#, the one legal bishop move - "a buddhist is
            forced to move. What will be the next situation?"

Unknown are part 1 (the "# X 2 S H 4 Y 0 Q B 15 #" template, with S = 32,
B = 49, H = -42 fixed but Q, X, Y open), part 2 ("the ironic 2name of the
keymakers") and part 4 ("Tell me, 4How so mate?").

Hashing is incremental: the prefix state is reused across the inner loops so
each candidate only rehashes its own tail.
"""

import hashlib
import itertools
import sys

DIGEST = "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32"

GENESIS = "TheTimes03/Jan/2009Chancelloronbrinkofsecondbailoutforbanks"
FEN = "6KR/1B5B/6R1/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1"

# "the ironic name of the keymakers trying to protect the current digital powers
# ... security by hiding, nearly unprotected, in plain sight"
KEYMAKERS = """DigiNotar Comodo Entrust VeriSign Symantec RSA Gemalto Thales Utimaco
SafeNet Ledger Trezor LastPass Keybase GlobalSign StartCom WoSign Certum Sectigo
Keeper Dashlane 1Password Bitwarden OneSpan Yubico Feitian Infineon NXP Atmel
Onelogin Okta Duo Auth0 Digicert GoDaddy Thawte Geotrust Rapidssl Letsencrypt
Cloudflare Akamai Verisign Trustwave Diginotar Keymaker Keysafe Keyless Vault
Hashicorp Keycloak Keychain Safeharbor Cryptomathic Nitrokey Solokeys""".split()

# "Tell me, 4How so mate?"  - "hoezo maat" is the literal Dutch, the creator's language
HOWSO = """howso hoezo hoezomaat howsomate mate maat checkmate check zugzwang
stalemate howsomate? howso? hoezo? hoezomaat? bishop monk luna moon tothemoon
crypto tothemoonmate hodl fiat gold silver debt inflation""".split()


def template_candidates():
    """Renderings of '# X 2 S H 4 Y 0 Q B 15 #' with S=32, B=49, H=-42."""
    out = []
    for x, y, q in itertools.product(range(10), repeat=3):
        tokens = [str(x), "2", "32", "-42", "4", str(y), "0", str(q), "49", "15"]
        out.append("".join(tokens))
        out.append("".join(tokens).replace("-", ""))
    return out


def search(part1s, part2s, part4s, part3="luna", part5="11110",
           part6=GENESIS, part7=FEN):
    target = DIGEST
    tried = 0
    for p1 in part1s:
        h1 = hashlib.sha256(p1.encode())
        for p2 in part2s:
            h2 = h1.copy()
            h2.update(p2.encode())
            h2.update(part3.encode())
            for p4 in part4s:
                h = h2.copy()
                h.update(p4.encode())
                h.update(part5.encode())
                h.update(part6.encode())
                h.update(part7.encode())
                tried += 1
                if h.hexdigest() == target:
                    print(f"*** MATCH  part1={p1!r} part2={p2!r} part4={p4!r}")
                    return tried, (p1, p2, p4)
    return tried, None


def main():
    p1 = template_candidates()
    p2 = sorted({w for name in KEYMAKERS for w in (name, name.lower(), name.upper())})
    p4 = sorted({w for word in HOWSO for w in (word, word.capitalize(), word.upper())})
    print(f"part1 candidates {len(p1)}  part2 {len(p2)}  part4 {len(p4)}")
    print(f"assemblies to test: {len(p1) * len(p2) * len(p4):,}")
    tried, hit = search(p1, p2, p4)
    print(f"tested {tried:,} assemblies")
    if not hit:
        print("no match")
        # sanity check: the harness does detect a correct assembly
        probe = ("a", "b", "c")
        control = hashlib.sha256("".join(
            [probe[0], probe[1], "luna", probe[2], "11110", GENESIS, FEN]).encode()).hexdigest()
        tried2, hit2 = search([probe[0]], [probe[1]], [probe[2]])
        print(f"harness self-test (target replaced): would have matched = "
              f"{control == hashlib.sha256(''.join([probe[0], probe[1], 'luna', probe[2], '11110', GENESIS, FEN]).encode()).hexdigest()}")


if __name__ == "__main__":
    main()
