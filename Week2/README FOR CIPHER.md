# Cyber Security — Project 2: Basic Encryption & Decryption

Industrial Training Kit · DecodeLabs · 2026 Batch

A command-line tool that implements the Caesar cipher (and a bonus
Vigenère cipher) to demonstrate the fundamentals of data confidentiality:
turning plaintext into ciphertext and reliably reversing the process.

## What this project does

- **Encrypts** user-supplied text using a basic substitution cipher
- **Decrypts** the resulting ciphertext back to the original text
- **Displays** plaintext, ciphertext, and decrypted text side by side
- **Validates** that `decrypt(encrypt(text)) == text` on every run

## Files

| File               | Purpose                                  |
|--------------------|-------------------------------------------|
| `cipher_project.py`| Full implementation + interactive CLI menu |
| `README.md`        | This file                                  |

## Requirements

- Python 3.7 or later (no external libraries needed)

## How to run

```bash
python3 cipher_project.py
```

You'll see a menu:

```
Choose an option:
  1) Caesar Cipher  (encrypt + decrypt + validate)
  2) Vigenere Cipher (bonus: multi-character key)
  3) Brute-force a Caesar ciphertext (see 'tiny key space' vulnerability)
  4) Exit
```

### Option 1 — Caesar Cipher
Enter any text and an integer shift key (press Enter for the default
shift of 3). The program encrypts it, decrypts it back, and confirms
the round trip matches the original.

Example:
```
Input      (Plaintext) : Hello, DecodeLabs! 2026
Process    (Shift key) : 3
Output     (Ciphertext): Khoor, GhfrghOdev! 2026
Decrypted  (Plaintext) : Hello, DecodeLabs! 2026
Validation             : PASSED ✔
```

### Option 2 — Vigenère Cipher (bonus)
Enter text and a keyword made of letters only (e.g. `LEMON`). Each
letter of the text is shifted by the corresponding letter of the
repeating keyword, giving a poly-alphabetic cipher that resists simple
frequency analysis better than Caesar's single shift.

### Option 3 — Brute Force Demo
Paste in Caesar ciphertext and the tool tries all 25 possible shifts,
illustrating why Caesar's tiny key space makes it "a lockbox, not a
vault."

### Option 4 — Exit

## How the math works

Encryption:
```
E_n(x) = (x + n) % 26
```
Decryption:
```
D_n(x) = (x - n) % 26
```
where `x` is a letter's position in the alphabet (A=0 … Z=25) and `n`
is the shift key. Python's `ord()` converts a character to its ASCII
value and `chr()` converts it back, e.g.:

```python
cipher_char = chr((ord(char) - 65 + shift) % 26 + 65)
```

## Edge cases handled

- Uppercase and lowercase letters are shifted independently and case
  is preserved
- Spaces, digits, punctuation, and symbols pass through unchanged
- Negative shifts or shifts greater than 26 are normalized with `%26`
- Blank input is rejected and re-prompted
- Vigenère keys must be non-empty and alphabetic

## Design notes

This is a **symmetric cipher**: the same key that encrypts also
decrypts, so `caesar_decrypt` is implemented internally as
`caesar_encrypt` with the shift negated.

Caesar and Vigenère are classroom/demo ciphers meant to teach the
core encrypt → decrypt (IPO) pattern. They are **not** suitable for
real-world security — modern systems use algorithms like AES-256,
which add key-dependent confusion and diffusion instead of a simple
alphabet shift. See the "Brute Force Demo" option for a hands-on look
at why.

## Possible extensions

- Support a full keyboard alphabet (numbers/symbols) instead of just A–Z
- Add file input/output so long messages can be encrypted from a `.txt` file
- Build a simple GUI or web front end around the same `caesar_*` /
  `vigenere_*` functions
- Implement frequency analysis to auto-crack unknown Caesar ciphertext

## Author

DecodeLabs Industrial Training Kit — Cyber Security Track, Project 2
