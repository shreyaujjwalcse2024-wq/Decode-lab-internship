# Password Strength Checker 🔐

![Tests](https://github.com/YOUR-USERNAME/YOUR-REPO-NAME/actions/workflows/tests.yml/badge.svg)

DecodeLabs Industrial Training Kit — Cyber Security, Project 1

A command-line tool that classifies a password as **Weak**, **Medium**, or
**Strong** using pure string-handling and conditional logic (no external
libraries required).

## What it checks
1. **Length** — rejects anything under 8 characters (per the slide's
   "Zero Point" rule); rewards 12+ characters.
2. **Character variety** — lowercase, UPPERCASE, digits, and symbols.
3. **Common / leaked passwords** — flags passwords found in a sample
   breach list (e.g. `password`, `123456`, `qwerty`).
4. **Predictable patterns** — repeated characters (`aaaa`) and simple
   sequences (`abcd`, `1234`, `qwerty`) drag the score down even if all
   four character types are present.

## How scoring works
| Condition | Result |
|---|---|
| In common-password list | Weak |
| Under 8 characters | Weak |
| Repeats/sequences found, or only 0–2 character types | Weak |
| 3–4 character types, under 12 chars | Medium |
| 3–4 character types, 12+ chars, no bad pattern | Strong |

## Run it
```bash
python password_checker.py
```
Then type any password to see its strength and feedback. Type `quit` to exit.

## Run the tests
```bash
python test_password_checker.py
```

## Ideas to extend it (from the training kit's conclusion)
- Load a much larger leaked-password list.
- Add an entropy/bits-of-randomness estimate instead of simple buckets.
- Use `hmac.compare_digest()` if you ever compare a password/hash against
  a stored value, to avoid timing-attack leaks (see slide 11).
