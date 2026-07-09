"""
Password Strength Checker
DecodeLabs Industrial Training Kit - Cyber Security Project 1

Checks a password against length, character-variety, and common-password
rules, then classifies it as WEAK, MEDIUM, or STRONG.

Run:
    python password_checker.py
"""

import re
import string

# ---------------------------------------------------------------------------
# A small sample of extremely common / leaked passwords.
# In a real product this would be loaded from a much larger breach list
# (e.g. "Have I Been Pwned" Pwned Passwords dataset).
# ---------------------------------------------------------------------------
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "letmein",
    "monkey", "111111", "iloveyou", "admin", "welcome", "password1",
    "123456789", "football", "dragon", "sunshine", "princess", "trustno1",
}

MIN_LENGTH = 8
GOOD_LENGTH = 12


def check_length(password: str) -> tuple[bool, str]:
    """Return (passes_minimum, feedback)."""
    if len(password) < MIN_LENGTH:
        return False, f"Too short (minimum {MIN_LENGTH} characters)."
    if len(password) < GOOD_LENGTH:
        return True, f"Meets the {MIN_LENGTH}-character minimum, but {GOOD_LENGTH}+ is safer."
    return True, "Good length."


def check_character_variety(password: str) -> dict:
    """Return which character classes are present in the password."""
    return {
        "lowercase": any(c.islower() for c in password),
        "uppercase": any(c.isupper() for c in password),
        "digit": any(c.isdigit() for c in password),
        "symbol": any(c in string.punctuation for c in password),
    }


def has_common_pattern(password: str) -> bool:
    """Flags obvious weak patterns: sequential digits/letters, repeats."""
    lowered = password.lower()

    # Repeated character run, e.g. "aaaa" or "1111"
    if re.search(r"(.)\1{3,}", password):
        return True

    # Simple ascending/descending sequences
    sequences = ["0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop"]
    for seq in sequences:
        for i in range(len(seq) - 3):
            chunk = seq[i:i + 4]
            if chunk in lowered or chunk[::-1] in lowered:
                return True

    return False


def is_common_password(password: str) -> bool:
    return password.lower() in COMMON_PASSWORDS


def score_password(password: str) -> tuple[str, list[str]]:
    """
    Runs every check and returns:
        strength: "Weak" | "Medium" | "Strong"
        feedback: list of human-readable notes
    """
    feedback = []

    # --- Immediate disqualifiers -----------------------------------------
    if is_common_password(password):
        return "Weak", ["This password appears in common leaked-password lists. Choose a different one."]

    length_ok, length_note = check_length(password)
    feedback.append(length_note)
    if not length_ok:
        return "Weak", feedback

    # --- Character variety scoring ----------------------------------------
    variety = check_character_variety(password)
    variety_score = sum(variety.values())  # 0-4

    missing = [name for name, present in variety.items() if not present]
    if missing:
        feedback.append("Missing character types: " + ", ".join(missing) + ".")
    else:
        feedback.append("Contains lowercase, uppercase, digits, and symbols.")

    # --- Pattern check -------------------------------------------------
    weak_pattern = has_common_pattern(password)
    if weak_pattern:
        feedback.append("Contains a predictable pattern (repeats or sequences like 'abcd'/'1234').")

    # --- Length bonus -------------------------------------------------
    long_bonus = len(password) >= GOOD_LENGTH

    # --- Final classification -------------------------------------------
    if variety_score <= 2 or weak_pattern:
        strength = "Weak"
    elif variety_score == 3 and not long_bonus:
        strength = "Medium"
    elif variety_score == 3 and long_bonus:
        strength = "Strong"
    elif variety_score == 4 and not long_bonus:
        strength = "Medium"
    else:  # variety_score == 4 and long_bonus
        strength = "Strong"

    return strength, feedback


def print_result(password: str) -> None:
    strength, feedback = score_password(password)

    bar = {"Weak": "🔴 WEAK", "Medium": "🟡 MEDIUM", "Strong": "🟢 STRONG"}[strength]

    print("\n" + "-" * 50)
    print(f"Password Strength: {bar}")
    print("-" * 50)
    for note in feedback:
        print(f" • {note}")
    print("-" * 50)


def main() -> None:
    print("=" * 50)
    print(" DecodeLabs Cyber Security - Password Strength Checker")
    print("=" * 50)
    print("Type a password to check it, or 'quit' to exit.\n")

    while True:
        password = input("Enter password: ").strip()
        if password.lower() in ("quit", "exit"):
            print("Goodbye!")
            break
        if not password:
            print("Please enter a non-empty password.\n")
            continue
        print_result(password)
        print()


if __name__ == "__main__":
    main()
