#!/usr/bin/env python3
"""
GSMG.IO 5 BTC Puzzle Solver
This script implements the solution logic for the GSMG.IO 5 BTC puzzle challenge.
"""

import hashlib
import base64
import subprocess
import sys
from typing import List, Tuple

# Import cipher_tools for Beaufort cipher
try:
    from cipher_tools import beaufort_cipher_decrypt
except ImportError:
    # Fallback if cipher_tools not available
    beaufort_cipher_decrypt = None


def sha256_hash(text: str) -> str:
    """Calculate SHA256 hash of text."""
    return hashlib.sha256(text.encode()).hexdigest()


def phase1_binary_matrix() -> str:
    """
    Phase 1: Decode the 14x14 binary matrix from https://gsmg.io/puzzle
    Returns the URL path: theseedisplanted
    """
    # Binary matrix from the puzzle
    matrix = [
        "00110100101100",
        "11110011101011",
        "11011101001001",
        "01101000011101",
        "01100011000110",
        "10011000100011",
        "10011100010000",
        "11100000001000",
        "00011101111101",
        "11111100110001",
        "11010000011011",
        "11110010101100",
        "01011101000110",
        "01101101101011"
    ]
    
    # Read spiral counterclockwise starting from top-left
    bits = []
    n = 14
    top, bottom, left, right = 0, n-1, 0, n-1
    
    # Start by going down the left column
    for i in range(top, bottom + 1):
        bits.append(matrix[i][left])
    left += 1
    
    # Go right along bottom
    for i in range(left, right + 1):
        bits.append(matrix[bottom][i])
    bottom -= 1
    
    # Go up the right column
    for i in range(bottom, top - 1, -1):
        bits.append(matrix[i][right])
    right -= 1
    
    # Go left along top
    for i in range(right, left - 1, -1):
        bits.append(matrix[top][i])
    top += 1
    
    # Continue spiral
    while left <= right and top <= bottom:
        # Down
        for i in range(top, bottom + 1):
            bits.append(matrix[i][left])
        left += 1
        
        # Right
        if left <= right:
            for i in range(left, right + 1):
                bits.append(matrix[bottom][i])
            bottom -= 1
        
        # Up
        if top <= bottom:
            for i in range(bottom, top - 1, -1):
                bits.append(matrix[i][right])
            right -= 1
        
        # Left
        if left <= right:
            for i in range(right, left - 1, -1):
                bits.append(matrix[top][i])
            top += 1
    
    # Convert bits to ASCII
    text = ""
    for i in range(0, len(bits), 8):
        if i + 8 <= len(bits):
            byte = bits[i:i+8]
            char_code = int(''.join(byte), 2)
            text += chr(char_code)
    
    return text


def phase2_decrypt(password: str, encrypted_file: str) -> str:
    """
    Phase 2: Decrypt AES-256-CBC encrypted content
    Password is SHA256(causality)
    """
    pwd_hash = sha256_hash(password)
    
    try:
        result = subprocess.run(
            ['openssl', 'enc', '-aes-256-cbc', '-d', '-a', '-in', encrypted_file,
             '-pass', f'pass:{pwd_hash}'],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Decryption failed: {e.stderr}"
    except FileNotFoundError:
        return "OpenSSL not found. Please install OpenSSL."


def phase3_build_password() -> str:
    """
    Phase 3: Build the concatenated password from 7 parts
    Returns SHA256 hash of the concatenated password
    """
    parts = [
        "causality",  # Part 1
        "Safenet",    # Part 2
        "Luna",       # Part 3
        "HSM",        # Part 4
        "11110",      # Part 5: JFK Executive Order 11110
        # Part 6: Genesis block raw data from Bitcoin source code line 1616
        # Hex decodes to: "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks"
        # This is the famous newspaper headline embedded in Bitcoin's first block
        "0x736B6E616220726F662074756F6C69616220646E6F63657320666F206B6E697262206E6F20726F6C6C65636E61684320393030322F6E614A2F33302073656D695420656854",
        "B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1"  # Part 7: Chess position notation
    ]
    
    concatenated = ''.join(parts)
    return sha256_hash(concatenated)


def phase3_2_build_password() -> str:
    """
    Phase 3.2: Build password for the second part of phase 3
    Returns SHA256 hash
    """
    parts = [
        "jacquefresco",                    # Jacque Fresco quote about "future is ours"
        "giveitjustonesecond",             # Alice in Wonderland reference
        "heisenbergsuncertaintyprinciple"  # Fundamental physics principle
    ]
    
    concatenated = ''.join(parts)
    return sha256_hash(concatenated)


def salphaseion_hash() -> str:
    """
    Salphaseion: Calculate the SHA256 hash to access the Salphaseion phase
    """
    text = "GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe"
    return sha256_hash(text)


def beaufort_decrypt(ciphertext: str, key: str) -> str:
    """
    Decrypt Beaufort cipher (wrapper for cipher_tools implementation)
    Beaufort cipher: P = K - C (mod 26)
    
    Args:
        ciphertext: Encrypted text
        key: Decryption key
    
    Returns:
        Decrypted plaintext
    
    Note: This is kept for backward compatibility.
    Use cipher_tools.beaufort_cipher_decrypt for the main implementation.
    """
    if beaufort_cipher_decrypt is not None:
        return beaufort_cipher_decrypt(ciphertext, key)
    
    # Fallback implementation if cipher_tools not available
    key = key.upper()
    ciphertext = ciphertext.upper()
    result = []
    key_index = 0
    
    for char in ciphertext:
        if char.isalpha():
            c = ord(char) - ord('A')
            k = ord(key[key_index % len(key)]) - ord('A')
            p = (k - c) % 26
            result.append(chr(p + ord('A')))
            key_index += 1
        else:
            result.append(char)
    
    return ''.join(result)


def binary_to_ascii(binary_str: str) -> str:
    """
    Convert binary string (using 'a' as 0 and 'b' as 1) to ASCII
    """
    binary_str = binary_str.replace('a', '0').replace('b', '1').replace(' ', '')
    text = ""
    for i in range(0, len(binary_str), 8):
        if i + 8 <= len(binary_str):
            byte = binary_str[i:i+8]
            char_code = int(byte, 2)
            text += chr(char_code)
    return text


def main():
    """Main execution function"""
    print("=" * 70)
    print("GSMG.IO 5 BTC PUZZLE SOLVER")
    print("=" * 70)
    
    # Phase 1
    print("\n[PHASE 1] Decoding binary matrix...")
    phase1_result = phase1_binary_matrix()
    # Extract just the path part if it includes domain
    if phase1_result.startswith("gsmg.io/"):
        path = phase1_result[8:]
    else:
        path = phase1_result
    print(f"Result: {phase1_result}")
    print(f"Path: {path}")
    
    # Phase 2
    print("\n[PHASE 2] Password for encrypted content...")
    password = "causality"
    pwd_hash = sha256_hash(password)
    print(f"Password: {password}")
    print(f"SHA256: {pwd_hash}")
    
    # Phase 3
    print("\n[PHASE 3] Building multi-part password...")
    phase3_pwd = phase3_build_password()
    print(f"Concatenated password hash: {phase3_pwd}")
    
    # Phase 3.2
    print("\n[PHASE 3.2] Building second password...")
    phase3_2_pwd = phase3_2_build_password()
    print(f"Concatenated password hash: {phase3_2_pwd}")
    
    # Salphaseion
    print("\n[SALPHASEION] Access hash...")
    sal_hash = salphaseion_hash()
    print(f"SHA256: {sal_hash}")
    print(f"Full URL: gsmg.io/{sal_hash}")
    
    # Binary decode example from Salphaseion
    print("\n[SALPHASEION DECODE] Binary segments...")
    binary1 = "a b b a b b a b a b b a a a a b a b b b a b a a a b b b a a b a a b b a b a a b a b b b b a a a a b b b a a b b a b b b a b a b a b b a b b a b a b b a b b a a a b b a b a a b a b b b a a b b a b b b a b a a"
    result1 = binary_to_ascii(binary1)
    print(f"Binary segment 1: {result1}")
    
    binary2 = "a b b a a b a b a b b a b b b a a b b b a b a a a b b a a b a b a b b b a a b a"
    result2 = binary_to_ascii(binary2)
    print(f"Binary segment 2: {result2}")
    
    # Beaufort cipher key
    print("\n[PHASE 3.2.1] Beaufort cipher key...")
    beaufort_key = "THEMATRIXHASYOU"
    print(f"Beaufort key: {beaufort_key}")
    
    print("\n" + "=" * 70)
    print("Solution complete!")
    print("=" * 70)
    print("\nNote: This script provides the passwords and hashes needed to")
    print("decrypt the various phases of the puzzle. The actual private key")
    print("retrieval requires completing all decryption steps with OpenSSL.")
    print("\nPrize address: 1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe")
    print("Current prize: 2.5 BTC (after halving)")
    print("=" * 70)


if __name__ == "__main__":
    main()
