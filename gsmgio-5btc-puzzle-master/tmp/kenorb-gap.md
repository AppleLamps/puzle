# GSMG.IO 5 BTC Puzzle - Comprehensive Gap Analysis

**Analysis Date:** December 2025
**Current Prize:** 2.5 BTC (was 5 BTC, halved May 2020)
**Status:** UNSOLVED

---

## Executive Summary

This document provides a comprehensive analysis of what has been solved and what remains unsolved in the GSMG.IO 5 BTC puzzle. The puzzle is multi-layered with at least **9+ encryption phases**. As of this analysis, Cosmic Duality has been decrypted but produces **encrypted binary output**, indicating additional layers remain.

---

## Phase Completion Status

### FULLY SOLVED PHASES

| Phase | Description | Solution |
|-------|-------------|----------|
| 1 | Binary Matrix (14x14) | Spiral decode → `gsmg.io/theseedisplanted` |
| 2 | Logic Song Reference | Hidden form, password: `theflowerblossomsthroughwhatseemstobeaconcretesurface` |
| 3 | Merovingian Quote | Password: `causality` → SHA256 for AES decryption |
| 3.1 | 7-Part Password | Combined: SafeNet Luna HSM + EO11110 + Bitcoin genesis + Chess |
| 3.2 | Three Riddles | Jacque Fresco + Alice in Wonderland + Heisenberg |
| 3.2.1 | Beaufort Cipher | Key: `THEMATRIXHASYOU` → Oracle's message |
| 3.2.2 | VIC Cipher | Alphabet from hints → "HALF AND BETTER HALF" message |
| Decentraland | Audio hint | Spectrogram reveals: `HASHTHETEXT` |
| SalPhaselon Entry | SHA256 hash | `SHA256(GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe)` |
| SalPhaselon | 7 Passwords | See below |
| Cosmic Duality | AES-256-CBC | Decrypted (produces binary output) |

### SalPhaselon 7 Passwords (SOLVED)

The seven passwords required to derive the Cosmic Duality decryption key:

1. `matrixsumlist` - From AB binary decode
2. `enter` - From AB binary decode
3. `lastwordsbeforearchichoice` - From z-separated segments
4. `thispassword` - From z-separated segments
5. `matrixsumlist` - Repeated (from theme analysis)
6. `yourlastcommand` - From "our first hint is your last command"
7. `secondanswer` - From "shabefanstoo" → "sha256 answer too"

**Derived Key:** `a795de117e472590e572dc193130c763e3fb555ee5db9d34494e156152e50735`

---

## UNSOLVED / PARTIALLY SOLVED ELEMENTS

### 1. Post-Cosmic Duality Layer(s) - CRITICAL

**Status:** UNSOLVED
**Priority:** HIGHEST

The Cosmic Duality decryption produces 1327 bytes of **encrypted binary data**, NOT plaintext:
- SHA256: `4f7a1e4efe4bf6c5581e32505c019657cb7b030e90232d33f011aca6a5e9c081`
- Entropy: 7.87 bits/byte (near-random, indicating encryption)
- First 32 bytes (hex): `44d19415009a2929a83b2f4e0da7b180d12f8b341cb879dd769ade1f8d399d40`

**Approaches NOT yet tried:**
- [ ] Using the 32-byte output as a direct private key
- [ ] Using the output SHA256 as another AES password
- [ ] XOR with remaining clues
- [ ] Bitcoin-specific key derivation (BIP32/BIP39)
- [ ] Check if output contains embedded structure

### 2. The X 2 S H 4 Y 0 Q B 15 Formula - PARTIALLY SOLVED

**Status:** PARTIALLY DECODED
**Known Values:**
- S = 32 (Klingon: 2 + (5×6))
- B = -16 ((5i - i)² = (4i)² = -16)

**Unknown Values:**
- H = "Answer to only this puzzle" × -1
- Y = Unknown
- Q = "Extend name of hackers' swordless fish, I and W below"
- X = Final result

**Not explored:**
- [ ] Q as "swordfishIW" or keyboard-related
- [ ] The formula's actual mathematical application
- [ ] Relationship to private key generation

### 3. The "HALF AND BETTER HALF" Hint

**Status:** UNDECODED
**Source:** VIC cipher output: "THE PRIVATE KEYS BELONG TO HALF AND BETTER HALF"

**Interpretations not tested:**
- [ ] Split the final key in half
- [ ] Two separate private keys needed
- [ ] Marriage/partner reference to the creator
- [ ] Mathematical half operation on key material

### 4. Oracle's Warning: Multiple Remaining Layers

**Quote from Phase 3.2.1:**
> "you will be required to select from over TWENTY-THREE CIPHERS, SIXTEEN ENCRYPTIONS and or SEVEN INTERTWINED PASSWORDS"

**Analysis:**
- If accurate, only ~5-7 cipher/encryption types have been identified
- Potentially 15+ more cryptographic operations remain
- Suggests brute-forcing may be required

### 5. SalPhaselon AES Blob (from README)

**Status:** NOT DECRYPTED
**Blob:** `U2FsdGVkX186tYU0hVJBXXUnBUO7C0+X4KUWnWkCvoZSxbRD3wNsGWVHefvdrd9z...`

This is DIFFERENT from Cosmic Duality and may contain additional clues.

### 6. Unused Clues and References

| Clue | Source | Status |
|------|--------|--------|
| Matrix themes (Neo, Architect, Oracle) | Throughout | Partially used |
| "Architect's choice" | SalPhaselon | Not applied |
| "Source codes" reference | Oracle message | Not explored |
| Norton's theorem | Phase 3 riddle | Connection unclear |
| Chess positions beyond initial | Phase 3 | Only one move decoded |
| Color significance (Red/White/Yellow/Blue) | Creator hint | Blue/Yellow=binary, Red/White unclear |

---

## Approaches NOT Yet Attempted (Detailed)

### 1. Elliptic Curve Operations (secp256k1)

Bitcoin uses the secp256k1 elliptic curve for all cryptographic operations. The puzzle may require EC math to derive the final private key.

**Specific approaches to try:**

```python
# Using the Cosmic Duality output as EC components
from ecdsa import SECP256k1, SigningKey, VerifyingKey

# Try 1: First 32 bytes as raw private key
cosmic_output_32 = bytes.fromhex("44d19415009a2929a83b2f4e0da7b180d12f8b341cb879dd769ade1f8d399d40")
try:
    sk = SigningKey.from_string(cosmic_output_32, curve=SECP256k1)
    print(f"Private key WIF: {sk.to_string().hex()}")
except:
    pass

# Try 2: Scalar multiplication with known points
# G = generator point of secp256k1
# Try: derived_key * G to see if result matches puzzle address

# Try 3: Point addition/subtraction with multiple derived values
# Combine the 7 password hashes using EC point operations instead of XOR

# Try 4: Check if output is a compressed/uncompressed public key
# 33 bytes (compressed) or 65 bytes (uncompressed)
```

**Untested EC operations:**
- [ ] Treat 1327-byte output as multiple EC points
- [ ] Use X 2 S H 4 Y 0 Q B 15 result as scalar multiplier
- [ ] Derive child keys using BIP32 with puzzle values as chain code
- [ ] Check if any 32-byte segment is valid private key for puzzle address
- [ ] Point halving operations (relates to "HALF AND BETTER HALF"?)

---

### 2. Key Derivation Functions (PBKDF2, scrypt)

The puzzle may use key stretching/derivation beyond simple SHA256.

**Specific approaches to try:**

```python
import hashlib
from Crypto.Protocol.KDF import PBKDF2, scrypt

# Known values to use as inputs
passwords = ["matrixsumlist", "enter", "lastwordsbeforearchichoice",
             "thispassword", "matrixsumlist", "yourlastcommand", "secondanswer"]
salt_candidates = [
    b"GSMG",
    b"gsmg.io",
    b"1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe",
    bytes.fromhex("2d3f6fe06dc950e6"),  # Cosmic Duality salt
    b"causality",
    b"THEMATRIXHASYOU",
]

# PBKDF2 attempts
for pwd in passwords:
    for salt in salt_candidates:
        for iterations in [1000, 10000, 100000, 2048, 4096]:
            key = PBKDF2(pwd.encode(), salt, dkLen=32, count=iterations)
            # Check if this produces valid private key for puzzle address

# scrypt attempts (Bitcoin uses N=16384, r=8, p=1 for BIP38)
for pwd in passwords:
    for salt in salt_candidates:
        key = scrypt(pwd.encode(), salt, key_len=32, N=16384, r=8, p=1)
        # Check against puzzle address
```

**Untested KDF operations:**
- [ ] PBKDF2 with concatenated passwords
- [ ] scrypt with Bitcoin BIP38 parameters
- [ ] Argon2id with puzzle-specific parameters
- [ ] HKDF (HMAC-based KDF) expansion
- [ ] bcrypt with known salts
- [ ] Use iteration count from puzzle clues (e.g., 1616 from Bitcoin source line)

---

### 3. Website Source Code Analysis

The gsmg.io website may contain hidden clues not yet discovered.

**Specific approaches to try:**

```bash
# Fetch and analyze main puzzle page
curl -s https://gsmg.io/puzzle > puzzle_page.html
curl -s https://gsmg.io/puzzle -I  # Check headers

# Look for hidden elements
grep -i "hidden\|display:none\|visibility:hidden" puzzle_page.html
grep -i "comment\|<!--" puzzle_page.html

# Check for JavaScript files
grep -oP 'src="[^"]*\.js"' puzzle_page.html | while read js; do
    curl -s "https://gsmg.io/$js" > "${js##*/}"
done

# Check robots.txt and sitemap
curl -s https://gsmg.io/robots.txt
curl -s https://gsmg.io/sitemap.xml

# Try common hidden endpoints
for path in admin api secret key private hidden .git .env config; do
    curl -s -o /dev/null -w "%{http_code} $path\n" "https://gsmg.io/$path"
done

# Check SSL certificate for hidden info
echo | openssl s_client -connect gsmg.io:443 2>/dev/null | openssl x509 -text

# Wayback Machine for historical versions
curl -s "https://web.archive.org/cdx/search/cdx?url=gsmg.io/*&output=json"
```

**Untested website analysis:**
- [ ] Full JavaScript deobfuscation and analysis
- [ ] WebSocket connections check
- [ ] Cookie/localStorage inspection
- [ ] API endpoint enumeration
- [ ] DNS TXT records for gsmg.io domain
- [ ] Historical page versions via Wayback Machine
- [ ] HTTP response header analysis (X-* headers)
- [ ] Check all known URLs for additional hidden forms

---

### 4. LSB Steganography in Images

The puzzle images may contain hidden data in least significant bits.

**Specific approaches to try:**

```python
from PIL import Image
import numpy as np

def extract_lsb(image_path, bits=1, channels='RGB'):
    """Extract LSB data from image"""
    img = Image.open(image_path)
    pixels = np.array(img)

    extracted_bits = []
    for channel in range(pixels.shape[2] if len(pixels.shape) > 2 else 1):
        for row in pixels:
            for pixel in row:
                if len(pixels.shape) > 2:
                    val = pixel[channel]
                else:
                    val = pixel
                for bit in range(bits):
                    extracted_bits.append((val >> bit) & 1)

    # Convert bits to bytes
    result = bytearray()
    for i in range(0, len(extracted_bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(extracted_bits):
                byte |= extracted_bits[i + j] << j
        result.append(byte)

    return bytes(result)

# Images to analyze
images = [
    "puzzle.png",
    "phase2.png",
    "phase3.png",
    "theseedisplanted.png",
    "SalPhaselonCosmicDuality.png",
    "photo_2020-04-26_09-24-30.jpg"
]

for img in images:
    for bits in [1, 2, 4]:
        data = extract_lsb(img, bits)
        # Check for known headers: PNG (89504E47), JPEG (FFD8FF), PK zip (504B0304)
        # Check for ASCII text
        # Check for base64 patterns
        # Check for "Salted__" AES header
```

**Untested steganography approaches:**
- [ ] LSB extraction in different bit orders (MSB first, row-wise, column-wise)
- [ ] Alpha channel analysis in PNG files (puzzle.png is RGBA)
- [ ] DCT coefficient analysis in JPEG (photo_2020-04-26_09-24-30.jpg)
- [ ] Palette-based steganography in indexed images
- [ ] Color histogram anomaly detection
- [ ] Fourier transform frequency domain analysis
- [ ] Blue/Yellow channel specific extraction (puzzle color scheme)
- [ ] Knight piece in puzzle.png - check pixels around it specifically
- [ ] QR code in puzzle.png - verify it decodes correctly, check for overlay data
- [ ] Check EXIF GPS coordinates for hidden meaning

---

### 5. Matrix Operations on 14×14 Binary

The original puzzle is a 14×14 binary matrix. Beyond spiral decoding, matrix math may reveal more.

**Specific approaches to try:**

```python
import numpy as np

# The original 14x14 binary matrix
matrix = np.array([
    [0,0,1,1,0,1,0,0,1,0,1,1,0,0],
    [1,1,1,1,0,0,1,1,1,0,1,0,1,1],
    [1,1,0,1,1,1,0,1,0,0,1,0,0,1],
    [0,1,1,0,1,0,0,0,0,1,1,1,0,1],
    [0,1,1,0,0,0,1,1,0,0,0,1,1,0],
    [1,0,0,1,1,0,0,0,1,0,0,0,1,1],
    [1,0,0,1,1,1,0,0,0,1,0,0,0,0],
    [1,1,1,0,0,0,0,0,0,0,1,0,0,0],
    [0,0,0,1,1,1,0,1,1,1,1,1,0,1],
    [1,1,1,1,1,1,0,0,1,1,0,0,0,1],
    [1,1,0,1,0,0,0,0,0,1,1,0,1,1],
    [1,1,1,1,0,0,1,0,1,0,1,1,0,0],
    [0,1,0,1,1,1,0,1,0,0,0,1,1,0],
    [0,1,1,0,1,1,0,1,1,0,1,0,1,1]
])

# Matrix operations to try:
# 1. Determinant (mod 2 for binary)
det = int(round(np.linalg.det(matrix))) % 2
print(f"Determinant mod 2: {det}")

# 2. Eigenvalues
eigenvalues = np.linalg.eigvals(matrix)
print(f"Eigenvalues: {eigenvalues}")

# 3. Matrix rank
rank = np.linalg.matrix_rank(matrix)
print(f"Rank: {rank}")

# 4. Row sums and column sums
row_sums = matrix.sum(axis=1)
col_sums = matrix.sum(axis=0)
print(f"Row sums: {row_sums}")  # Could be ASCII or key bytes
print(f"Col sums: {col_sums}")

# 5. Diagonal elements
main_diag = np.diag(matrix)
anti_diag = np.diag(np.fliplr(matrix))
print(f"Main diagonal: {main_diag}")
print(f"Anti diagonal: {anti_diag}")

# 6. Matrix multiplication with itself
squared = np.matmul(matrix, matrix)
# Check if result encodes anything

# 7. XOR with key matrix (derived from passwords?)
# 8. Transpose and re-read spiral
# 9. Rotate 90/180/270 degrees and decode
# 10. Read in different spiral directions (clockwise, from other corners)
```

**Untested matrix operations:**
- [ ] Matrix inverse (if exists) in GF(2)
- [ ] Row reduction / RREF form
- [ ] LU decomposition
- [ ] Treat as adjacency matrix for graph analysis
- [ ] Conway's Game of Life iterations
- [ ] Cellular automata rules (Rule 30, Rule 110)
- [ ] 2D Fourier transform
- [ ] Row/column permutations based on password orderings
- [ ] Stack multiple matrices from different phases
- [ ] Use matrix as transformation for other puzzle data

---

### 6. XOR Chains with All Passwords

Multi-step XOR operations may reveal hidden data.

**Specific approaches to try:**

```python
import hashlib

# All known significant strings
all_strings = [
    # Phase passwords
    "theflowerblossomsthroughwhatseemstobeaconcretesurface",
    "causality",
    "Safenet", "Luna", "HSM",
    "11110",
    "0x736B6E616220726F662074756F6C69616220646E6F63657320666F206B6E697262206E6F20726F6C6C65636E61684320393030322F6E614A2F33302073656D695420656854",
    "B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1",

    # SalPhaselon passwords
    "matrixsumlist", "enter", "lastwordsbeforearchichoice",
    "thispassword", "yourlastcommand", "secondanswer",

    # Other significant values
    "THEMATRIXHASYOU",
    "jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple",
    "HASHTHETEXT",
    "gsmg.io/theseedisplanted",
    "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe",
    "GSMGIO5BTCPUZZLECHALLENGE",
]

# Known hashes
hashes = {
    "causality": "eb3efb5151e6255994711fe8f2264427ceeebf88109e1d7fad5b0a8b6d07e5bf",
    "7part": "1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5",
    "phase32": "250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c",
    "salphaselon_entry": "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32",
    "cosmic_key": "a795de117e472590e572dc193130c763e3fb555ee5db9d34494e156152e50735",
    "cosmic_output": "4f7a1e4efe4bf6c5581e32505c019657cb7b030e90232d33f011aca6a5e9c081",
}

def xor_bytes(a, b):
    """XOR two byte sequences, cycling shorter one"""
    result = bytearray()
    for i in range(max(len(a), len(b))):
        result.append(a[i % len(a)] ^ b[i % len(b)])
    return bytes(result)

# XOR all hashes together in sequence
result = bytes.fromhex(hashes["causality"])
for name, h in list(hashes.items())[1:]:
    result = xor_bytes(result, bytes.fromhex(h))
    print(f"After XOR with {name}: {result.hex()[:32]}...")

# XOR cosmic output with various values
cosmic_output_bytes = bytes.fromhex("44d19415009a2929a83b2f4e0da7b180d12f8b341cb879dd769ade1f8d399d40")
for s in all_strings:
    xored = xor_bytes(cosmic_output_bytes, s.encode())
    # Check if result is valid private key / printable / meaningful

# XOR with Bitcoin address bytes
btc_addr = "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
import base58
try:
    addr_bytes = base58.b58decode(btc_addr)
    xored = xor_bytes(cosmic_output_bytes, addr_bytes)
    print(f"XOR with BTC address: {xored.hex()}")
except:
    pass
```

**Untested XOR operations:**
- [ ] XOR all SHA256 hashes in different orders (7! = 5040 permutations)
- [ ] XOR with Bitcoin address decoded bytes
- [ ] XOR pairs of derived values and check results
- [ ] Rolling XOR with password bytes
- [ ] XOR first half with second half of Cosmic output ("HALF AND BETTER HALF"?)
- [ ] XOR with known Bitcoin genesis block data
- [ ] XOR with the binary matrix flattened to bytes
- [ ] Create XOR chain: output[i] = data[i] XOR key[i] XOR output[i-1]

---

### 7. Additional Cryptographic Approaches

**Block Cipher Variations:**
- [ ] AES-128 instead of AES-256
- [ ] AES-ECB mode (no IV)
- [ ] AES-CTR mode
- [ ] Triple DES
- [ ] Blowfish / Twofish
- [ ] ChaCha20

**Hash Variations:**
- [ ] SHA-512 instead of SHA-256
- [ ] RIPEMD-160 (used in Bitcoin addresses)
- [ ] Double SHA256 (Bitcoin standard)
- [ ] SHA256(SHA256(x)) for all derived values
- [ ] HMAC-SHA256 with puzzle keys

**Bitcoin-Specific:**
- [ ] WIF encoding/decoding attempts
- [ ] BIP39 mnemonic derivation
- [ ] BIP32 hierarchical deterministic paths
- [ ] Mini private key format (22-30 chars starting with S)
- [ ] Brain wallet derivation from puzzle phrases

---

## Recommended Next Steps

### Priority 1: Analyze Cosmic Duality Output
```python
# The 1327-byte output needs:
# 1. Structure analysis (look for magic bytes)
# 2. Try as raw private key
# 3. Use first/last 32 bytes as key
# 4. Check for BIP39 seed compatibility
```

### Priority 2: Solve X 2 S H 4 Y 0 Q B 15
- Research "swordfish" movie/hack references for Q
- Determine H (puzzle answer × -1)
- Apply formula to get X

### Priority 3: Decrypt SalPhaselon AES Blob
- Try variations of the 7 passwords
- Try Cosmic Duality output as password

### Priority 4: Investigate "Half and Better Half"
- Consider key splitting operations
- Research if creator has a partner/co-creator

---

## Technical Reference

### Known Working Commands
```bash
# Phase 3 decryption
openssl enc -aes-256-cbc -d -a -in phase3.txt -pass pass:1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5

# Cosmic Duality key derivation
# XOR of SHA256 hashes of 7 passwords
# Key: a795de117e472590e572dc193130c763e3fb555ee5db9d34494e156152e50735
```

### Prize Address
```
Address: 1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe
Required: WIF private key (51 characters starting with 5, K, or L)
```

---

## Sources

- [GitHub Repository](https://github.com/puzzlehunt/gsmgio-5btc-puzzle)
- [Issue #55: Cosmic Duality Decryption](https://github.com/puzzlehunt/gsmgio-5btc-puzzle/issues/55)
- [jackdevs66 Solution Repo](https://github.com/jackdevs66/GSMG5_CDuality)
- [Reddit Discussion](https://www.reddit.com/r/bitcoinpuzzles/comments/dfwcqk/gsmgio_5_btc_puzzle/)
- [Private Keys Directory](https://privatekeys.pw/puzzles/gsmg-puzzle)

---

## Conclusion

The puzzle has been solved up to and including **Cosmic Duality decryption**, but the output is another encrypted layer. The final private key has NOT been extracted. Based on the Oracle's warning about "23 ciphers, 16 encryptions, and 7 passwords," there may be **10-15 more decryption layers** remaining.

The most promising immediate avenue is analyzing the 1327-byte Cosmic Duality output, as it's the current "frontier" of the puzzle. The X 2 S H 4 Y 0 Q B 15 formula also remains partially unsolved and may be key to the next step.

**Estimated remaining work:** Significant - potentially weeks to months of cryptanalysis.
