"""
DecodeLabs Industrial Training Kit — Cyber Security | Project 2
Basic Encryption & Decryption
=================================================================

Goal (per project brief):
  1. Encrypt user text using a basic logic (Caesar cipher or similar)
  2. Decrypt the encrypted text
  3. Display both encrypted and decrypted output

This implementation follows the IPO model and math shown in the kit:
    E_n(x) = (x + n) % 26        (encryption)
    D_n(x) = (x - n) % 26        (decryption)

It also includes the two "experiment" ideas suggested in the kit's
conclusion slide:
  - A user-selectable shift key (instead of a hardcoded shift)
  - A slightly more complex Vigenère cipher (multi-character key)

Edge cases handled:
  - Uppercase and lowercase letters shifted independently (case preserved)
  - Spaces, punctuation, numbers, and symbols pass through unchanged
  - Negative shifts and shifts > 26 are normalized with modulo
  - Empty input, non-alphabetic-only input, invalid menu choices

Author: DecodeLabs Intern Track — 2026 Batch
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# 1. CAESAR CIPHER  (single integer key, mono-alphabetic substitution)
# ---------------------------------------------------------------------------

def caesar_encrypt(plaintext: str, shift: int) -> str:
    """Encrypt plaintext with a Caesar shift, per E_n(x) = (x + n) % 26."""
    shift = shift % 26  # normalize so shift always lands in [0, 25]
    result = []
    for char in plaintext:
        if char.isupper():
            result.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
        elif char.islower():
            result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
        else:
            # Edge case: spaces, punctuation, digits pass through untouched
            result.append(char)
    return "".join(result)


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    """Decrypt ciphertext with a Caesar shift, per D_n(x) = (x - n) % 26.

    Symmetric encryption: the same key that locked the text unlocks it,
    so decryption is simply encryption with the negated shift.
    """
    return caesar_encrypt(ciphertext, -shift)


# ---------------------------------------------------------------------------
# 2. VIGENERE CIPHER  (bonus: multi-character key, poly-alphabetic)
# ---------------------------------------------------------------------------

def _vigenere_transform(text: str, key: str, encrypting: bool) -> str:
    """Shared engine for Vigenere encrypt/decrypt.

    Each letter of `text` is shifted by the corresponding letter of `key`
    (repeating the key as needed). Non-alphabetic characters are passed
    through unchanged AND do not consume a position in the key, so
    "HELLO, WORLD!" encrypts predictably regardless of punctuation.
    """
    if not key or not key.isalpha():
        raise ValueError("Vigenere key must be a non-empty alphabetic string.")

    key = key.upper()
    result = []
    key_index = 0
    key_len = len(key)

    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % key_len]) - ord('A')
            if not encrypting:
                shift = -shift

            if char.isupper():
                result.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
            else:
                result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))

            key_index += 1  # only alphabetic chars advance the key
        else:
            result.append(char)

    return "".join(result)


def vigenere_encrypt(plaintext: str, key: str) -> str:
    return _vigenere_transform(plaintext, key, encrypting=True)


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    return _vigenere_transform(ciphertext, key, encrypting=False)


# ---------------------------------------------------------------------------
# 3. VALIDATION HELPER — proves encryption/decryption are true inverses
# ---------------------------------------------------------------------------

def validate_roundtrip(original: str, decrypted: str) -> bool:
    """Confirm decrypt(encrypt(x)) == x, as required by the qualification
    criteria ("Validate with Decryption Function")."""
    return original == decrypted


# ---------------------------------------------------------------------------
# 4. INPUT HELPERS
# ---------------------------------------------------------------------------

def prompt_int(prompt_text: str, default: int) -> int:
    """Read an integer from the user, tolerating blank/invalid input."""
    raw = input(prompt_text).strip()
    if raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        print(f"  (Not a valid number — using default shift of {default}.)")
        return default


def prompt_nonempty(prompt_text: str) -> str:
    """Keep asking until the user provides non-empty text."""
    while True:
        raw = input(prompt_text)
        if raw.strip() != "":
            return raw
        print("  Input cannot be empty. Please try again.")


# ---------------------------------------------------------------------------
# 5. CLI — MENU-DRIVEN DEMO
# ---------------------------------------------------------------------------

def run_caesar_demo() -> None:
    print("\n--- Caesar Cipher ---")
    text = prompt_nonempty("Enter text to encrypt: ")
    shift = prompt_int("Enter shift key (integer, default 3): ", default=3)

    encrypted = caesar_encrypt(text, shift)
    decrypted = caesar_decrypt(encrypted, shift)
    ok = validate_roundtrip(text, decrypted)

    print("\nIPO Summary")
    print(f"  Input      (Plaintext) : {text}")
    print(f"  Process    (Shift key) : {shift}")
    print(f"  Output     (Ciphertext): {encrypted}")
    print(f"  Decrypted  (Plaintext) : {decrypted}")
    print(f"  Validation             : {'PASSED ✔' if ok else 'FAILED ✘'}")


def run_vigenere_demo() -> None:
    print("\n--- Vigenere Cipher (bonus) ---")
    text = prompt_nonempty("Enter text to encrypt: ")
    while True:
        key = input("Enter an alphabetic key word (e.g. LEMON): ").strip()
        if key.isalpha() and key != "":
            break
        print("  Key must contain letters only. Try again.")

    encrypted = vigenere_encrypt(text, key)
    decrypted = vigenere_decrypt(encrypted, key)
    ok = validate_roundtrip(text, decrypted)

    print("\nIPO Summary")
    print(f"  Input      (Plaintext) : {text}")
    print(f"  Process    (Key)       : {key.upper()}")
    print(f"  Output     (Ciphertext): {encrypted}")
    print(f"  Decrypted  (Plaintext) : {decrypted}")
    print(f"  Validation             : {'PASSED ✔' if ok else 'FAILED ✘'}")


def run_brute_force_demo() -> None:
    """Illustrates the kit's 'Vulnerability' slide: a Caesar cipher only
    has 25 possible keys, so ciphertext can be brute-forced instantly."""
    print("\n--- Brute Force All 25 Shifts (educational) ---")
    ciphertext = prompt_nonempty("Enter Caesar ciphertext to brute-force: ")
    for shift in range(1, 26):
        print(f"  shift {shift:>2}: {caesar_decrypt(ciphertext, shift)}")


def main() -> None:
    print("=" * 60)
    print("  DECODELABS | Cyber Security Project 2")
    print("  Basic Encryption & Decryption")
    print("=" * 60)

    menu = """
Choose an option:
  1) Caesar Cipher  (encrypt + decrypt + validate)
  2) Vigenere Cipher (bonus: multi-character key)
  3) Brute-force a Caesar ciphertext (see 'tiny key space' vulnerability)
  4) Exit
> """

    while True:
        choice = input(menu).strip()
        if choice == "1":
            run_caesar_demo()
        elif choice == "2":
            run_vigenere_demo()
        elif choice == "3":
            run_brute_force_demo()
        elif choice == "4":
            print("Session complete. Ciphertext generated. Badge earned. 🛡")
            break
        else:
            print("  Invalid choice — please enter 1, 2, 3, or 4.")


if __name__ == "__main__":
    main()
