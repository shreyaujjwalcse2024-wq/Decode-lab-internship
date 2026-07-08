"""
DecodeLabs Industrial Training Kit — Cyber Security | Project 3
Phishing Awareness Analysis
=================================================================

Goal (per project brief):
  1. Analyze sample emails or messages to identify phishing attempts
  2. Identify suspicious links or keywords
  3. List red flags found in phishing messages
  4. Explain why the message is unsafe

This is a defensive, educational triage tool. It does NOT send email,
click links, or execute attachments — it only reads text you provide
and reports on known social-engineering red flags, mirroring the
Pause -> Verify -> Report workflow and the Safe/Suspicious/Malicious
decision tree from the training kit.

Author: DecodeLabs Intern Track — 2026 Batch
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# 1. DATA MODEL
# ---------------------------------------------------------------------------

@dataclass
class Email:
    """A minimal representation of an email/message to analyze."""
    display_name: str      # e.g. "Microsoft Support"
    from_address: str      # e.g. "support@logins-updates.com"
    subject: str
    body: str
    attachments: list = field(default_factory=list)   # e.g. ["Invoice.exe"]
    expected_domain: str = ""  # the real company domain this claims to be from


@dataclass
class RedFlag:
    """A single detected indicator, with severity and explanation."""
    name: str
    severity: int          # 1 = low, 2 = medium, 3 = high
    detail: str


# ---------------------------------------------------------------------------
# 2. REFERENCE DATA
# ---------------------------------------------------------------------------

URGENCY_KEYWORDS = [
    "urgent", "immediately", "act now", "act fast", "expires in",
    "final notice", "account suspended", "account locked",
    "verify your account", "confirm your identity", "limited time",
    "failure to respond", "within 24 hours", "asap",
]

FEAR_AUTHORITY_KEYWORDS = [
    "legal action", "will be terminated", "law enforcement",
    "unauthorized access detected", "suspicious activity",
    "your account will be closed", "strictly confidential",
    "do not discuss", "bypass standard procedure", "bypass normal",
]

FINANCIAL_KEYWORDS = [
    "wire transfer", "gift card", "bank details", "routing number",
    "payment failed", "update billing", "invoice attached",
    "purchase order", "transfer funds",
]

SENSITIVE_INFO_KEYWORDS = [
    "password", "otp", "one-time code", "mfa code", "verification code",
    "ssn", "social security", "cvv", "pin number",
]

DANGEROUS_ATTACHMENT_EXTENSIONS = {
    ".exe", ".scr", ".js", ".vbs", ".iso", ".bat", ".cmd",
    ".jar", ".hta", ".lnk", ".docm", ".xlsm", ".msi",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly",
}

KNOWN_BRAND_DOMAINS = {
    "amazon.com", "paypal.com", "microsoft.com", "google.com",
    "apple.com", "netflix.com", "facebook.com", "chatgpt.com",
    "openai.com", "bankofamerica.com", "linkedin.com", "instagram.com",
}

URL_PATTERN = re.compile(r"https?://[^\s)>\]\"']+", re.IGNORECASE)
IP_URL_PATTERN = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}")


# ---------------------------------------------------------------------------
# 3. HELPERS
# ---------------------------------------------------------------------------

def extract_domain(address_or_url: str) -> str:
    """Pull the domain out of an email address or URL."""
    text = address_or_url.strip().lower()
    if "@" in text:
        text = text.split("@")[-1]
    else:
        text = re.sub(r"^https?://", "", text)
        text = text.split("/")[0]
    return text.strip(">.")


def registrable_root(domain: str) -> str:
    """Naive 'true root domain' extractor: last two labels.
    E.g. 'www.decodelabs.tech.login-update.com' -> 'login-update.com'.
    Good enough for teaching the 'read URLs right to left' lesson;
    not a substitute for a real public-suffix-list parser.
    """
    parts = [p for p in domain.split(".") if p]
    if len(parts) < 2:
        return domain
    return ".".join(parts[-2:])


def levenshtein(a: str, b: str) -> int:
    """Classic edit-distance, used to catch typosquatted brand domains
    like 'amaz0n.com' or 'paypa1.com'."""
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
        prev = cur
    return prev[-1]


NEGATION_PHRASES = [
    "non-urgent", "not urgent", "no immediate action", "no action required",
    "no action needed", "not required",
]


def contains_any(haystack: str, needles: list) -> list:
    """Case-insensitive substring match, with a lightweight guard against
    common negated phrasing (e.g. 'Non-Urgent' should not trip 'urgent')."""
    haystack_lower = haystack.lower()
    for phrase in NEGATION_PHRASES:
        haystack_lower = haystack_lower.replace(phrase, "")
    return [n for n in needles if n in haystack_lower]


# ---------------------------------------------------------------------------
# 4. RED-FLAG DETECTORS
# ---------------------------------------------------------------------------

def check_sender_domain_mismatch(email: Email) -> RedFlag | None:
    """Red Flag 1: display name claims one brand, but the routing
    domain doesn't match that brand's real domain."""
    domain = extract_domain(email.from_address)
    name_lower = email.display_name.lower()

    for brand in KNOWN_BRAND_DOMAINS:
        brand_word = brand.split(".")[0]
        if brand_word in name_lower and not domain.endswith(brand):
            return RedFlag(
                "Sender-Domain Mismatch",
                3,
                f"Display name '{email.display_name}' implies {brand}, "
                f"but the message actually routes through '{domain}'.",
            )

    if email.expected_domain and not domain.endswith(email.expected_domain):
        return RedFlag(
            "Sender-Domain Mismatch",
            3,
            f"Expected mail from '{email.expected_domain}' but the From "
            f"address domain is '{domain}'.",
        )
    return None


def check_typosquatting(email: Email) -> RedFlag | None:
    """Red Flag: lookalike domain within 1-2 edits of a known brand."""
    domain = extract_domain(email.from_address)
    for brand in KNOWN_BRAND_DOMAINS:
        dist = levenshtein(domain, brand)
        if 0 < dist <= 2:
            return RedFlag(
                "Typosquatting / Lookalike Domain",
                3,
                f"Sender domain '{domain}' is suspiciously close to the "
                f"legitimate '{brand}' (edit distance {dist}).",
            )
    return None


def check_subdomain_trap(email: Email) -> list[RedFlag]:
    """Red Flag: a trusted brand name is buried as a fake subdomain in
    front of an unrelated true root domain, e.g.
    'accounts.google.com.verify-secure.net'."""
    flags = []
    body_urls = URL_PATTERN.findall(email.body)
    for url in body_urls:
        domain = extract_domain(url)
        root = registrable_root(domain)
        for brand in KNOWN_BRAND_DOMAINS:
            brand_word = brand.split(".")[0]
            if brand_word in domain and not domain.endswith(brand) and root != brand:
                flags.append(RedFlag(
                    "Subdomain Trap",
                    3,
                    f"Link '{url}' buries '{brand_word}' as a fake "
                    f"subdomain; the true root domain is '{root}', not {brand}.",
                ))
    return flags


def check_urgency_and_pressure(email: Email) -> list[RedFlag]:
    flags = []
    text = f"{email.subject} {email.body}"

    hits = contains_any(text, URGENCY_KEYWORDS)
    if hits:
        flags.append(RedFlag(
            "Urgency / Time Pressure",
            2,
            f"Contains urgency language: {', '.join(hits[:4])}.",
        ))

    hits = contains_any(text, FEAR_AUTHORITY_KEYWORDS)
    if hits:
        flags.append(RedFlag(
            "Fear or Authority Pressure",
            3,
            f"Contains fear/authority language: {', '.join(hits[:4])}.",
        ))

    hits = contains_any(text, FINANCIAL_KEYWORDS)
    if hits:
        flags.append(RedFlag(
            "Financial Bait",
            3,
            f"References money movement or billing: {', '.join(hits[:4])}.",
        ))

    hits = contains_any(text, SENSITIVE_INFO_KEYWORDS)
    if hits:
        flags.append(RedFlag(
            "Request for Sensitive Info",
            3,
            f"Asks for sensitive credentials/codes: {', '.join(hits[:4])}.",
        ))

    return flags


def check_links(email: Email) -> list[RedFlag]:
    flags = []
    urls = URL_PATTERN.findall(email.body)

    for url in urls:
        if IP_URL_PATTERN.match(url):
            flags.append(RedFlag(
                "Raw IP Address Link",
                3,
                f"Link uses a raw IP address instead of a domain: {url}",
            ))

        domain = extract_domain(url)
        if any(domain == s or domain.endswith("." + s) for s in URL_SHORTENERS):
            flags.append(RedFlag(
                "URL Shortener",
                2,
                f"Link uses a shortener ('{domain}') which hides the real "
                f"destination: {url}",
            ))

        if domain.count(".") >= 4:
            flags.append(RedFlag(
                "Excessive Subdomains",
                1,
                f"Link has an unusually deep subdomain chain: {domain}",
            ))

    # Mismatched anchor text vs href, written as "click here (http://...)"
    # or "[Bank of America](http://fake.com)" style in plaintext samples.
    md_links = re.findall(r"\[([^\]]+)\]\((https?://[^\s)]+)\)", email.body)
    for anchor_text, url in md_links:
        anchor_domain_guess = anchor_text.lower().replace(" ", "")
        real_domain = extract_domain(url)
        if anchor_text.strip() and anchor_domain_guess not in real_domain \
                and not any(b.split(".")[0] in anchor_domain_guess and real_domain.endswith(b)
                            for b in KNOWN_BRAND_DOMAINS):
            flags.append(RedFlag(
                "Anchor Text / Destination Mismatch",
                3,
                f"Link text '{anchor_text}' does not match its real "
                f"destination '{url}'.",
            ))

    return flags


def check_attachments(email: Email) -> list[RedFlag]:
    flags = []
    for attachment in email.attachments:
        lower = attachment.lower()
        for ext in DANGEROUS_ATTACHMENT_EXTENSIONS:
            if lower.endswith(ext):
                flags.append(RedFlag(
                    "Dangerous Attachment",
                    3,
                    f"Attachment '{attachment}' uses a high-risk extension "
                    f"('{ext}') commonly used to deliver malware.",
                ))
        if lower.count(".") >= 2 and not any(lower.endswith(e) for e in (".pdf", ".docx", ".xlsx", ".pptx", ".png", ".jpg")):
            flags.append(RedFlag(
                "Double Extension",
                2,
                f"Attachment '{attachment}' has multiple extensions, a "
                f"classic trick to disguise an executable as a document.",
            ))
    return flags


def check_generic_greeting(email: Email) -> RedFlag | None:
    body_start = email.body.strip()[:60].lower()
    if any(g in body_start for g in ("dear customer", "dear user", "dear valued", "dear account holder")):
        return RedFlag(
            "Generic Greeting",
            1,
            "Uses a generic greeting instead of your actual name, "
            "suggesting a mass-distributed lure rather than a personal message.",
        )
    return None


DETECTORS = [
    check_sender_domain_mismatch,
    check_typosquatting,
    check_subdomain_trap,
    check_urgency_and_pressure,
    check_links,
    check_attachments,
    check_generic_greeting,
]


# ---------------------------------------------------------------------------
# 5. TRIAGE ENGINE — analyze, score, classify
# ---------------------------------------------------------------------------

def analyze_email(email: Email) -> tuple[list[RedFlag], int, str, str]:
    """Run all detectors, score the result, and classify per the kit's
    Safe / Suspicious / Malicious decision tree."""
    flags: list[RedFlag] = []

    for detector in DETECTORS:
        result = detector(email)
        if result is None:
            continue
        if isinstance(result, list):
            flags.extend(result)
        else:
            flags.append(result)

    score = sum(f.severity for f in flags)

    if score == 0:
        verdict, action = "SAFE", "Close — no action needed."
    elif score <= 3:
        verdict, action = "SUSPICIOUS", "Warn User — verify via a separate, known channel before acting."
    else:
        verdict, action = "MALICIOUS", "Block & Escalate — report to security team immediately, do not click or reply."

    return flags, score, verdict, action


def print_report(email: Email) -> None:
    flags, score, verdict, action = analyze_email(email)

    print("\n" + "=" * 70)
    print(f"SUBJECT : {email.subject}")
    print(f"FROM    : {email.display_name} <{email.from_address}>")
    print("=" * 70)

    if not flags:
        print("No red flags detected.")
    else:
        print(f"Red flags found ({len(flags)}):\n")
        for i, f in enumerate(flags, 1):
            stars = "★" * f.severity + "☆" * (3 - f.severity)
            print(f"  {i}. [{stars}] {f.name}")
            print(f"     -> {f.detail}\n")

    print(f"Risk Score : {score}")
    print(f"Verdict    : {verdict}")
    print(f"Action     : {action}")
    print("=" * 70)


# ---------------------------------------------------------------------------
# 6. SAMPLE MESSAGES (for demo / testing without needing real phishing mail)
# ---------------------------------------------------------------------------

SAMPLES = {
    "1": Email(
        display_name="Microsoft Support",
        from_address="support@logins-updates.com",
        subject="FW: Urgent Your Account Security Alert",
        body=(
            "Dear valued customer, we detected suspicious activity on your account. "
            "Your account will be suspended within 24 hours unless you verify your "
            "identity immediately. Click here to confirm: "
            "http://accounts.microsoft.com.logins-updates.com/verify\n"
            "Please do not discuss this with anyone and bypass standard procedure "
            "to resolve this urgently."
        ),
        attachments=["Security_Update_2024.iso"],
        expected_domain="microsoft.com",
    ),
    "2": Email(
        display_name="CEO Name",
        from_address="ceo.urgent@executive-update.com",
        subject="IMMEDIATE ACTION REQUIRED: Transfer Authorization",
        body=(
            "URGENT: Process the attached wire transfer instruction immediately. "
            "This is critical and must remain strictly confidential. "
            "Do not discuss with anyone. Bypass standard procedure. Thank you."
        ),
        attachments=["Wire_Instructions.docm"],
        expected_domain="decodelabs.tech",
    ),
    "3": Email(
        display_name="Sarah Lee",
        from_address="sarah.lee@company.com",
        subject="Q3 Project Status Update - Non-Urgent",
        body=(
            "Hi Team,\nPlease review the attached project status for Q3 at your "
            "earliest convenience. No immediate action is required.\nThanks,\nSarah."
        ),
        attachments=["Q3_Status.pdf"],
        expected_domain="company.com",
    ),
    "4": Email(
        display_name="ChatGPT Billing",
        from_address="billing@chatgpt-payments-secure.net",
        subject="Urgent: ChatGPT Payment Failure",
        body=(
            "Your subscription payment failed. Please update your billing "
            "information immediately to avoid service interruption. "
            "[Update Billing](http://bit.ly/3xUpdate)"
        ),
        attachments=[],
        expected_domain="openai.com",
    ),
}


# ---------------------------------------------------------------------------
# 7. INPUT HELPERS
# ---------------------------------------------------------------------------

def prompt_nonempty(prompt_text: str) -> str:
    while True:
        raw = input(prompt_text)
        if raw.strip() != "":
            return raw
        print("  Input cannot be empty. Please try again.")


def build_email_from_input() -> Email:
    print("\nEnter the message details (paste plain text is fine).")
    display_name = prompt_nonempty("Sender display name: ")
    from_address = prompt_nonempty("Sender email address: ")
    subject = input("Subject: ").strip()
    print("Body (end input with a single line containing only END):")
    lines = []
    while True:
        line = input()
        if line.strip() == "END":
            break
        lines.append(line)
    body = "\n".join(lines)
    attachments_raw = input("Attachment filenames, comma-separated (or blank): ").strip()
    attachments = [a.strip() for a in attachments_raw.split(",") if a.strip()]
    expected_domain = input("Expected/legitimate domain, if known (or blank): ").strip()
    return Email(display_name, from_address, subject, body, attachments, expected_domain)


# ---------------------------------------------------------------------------
# 8. CLI — MENU-DRIVEN DEMO
# ---------------------------------------------------------------------------

def show_red_flag_reference() -> None:
    print("""
Red Flag Reference Guide
-------------------------
1. Sender-Domain Mismatch  — display name says Brand X, routing domain doesn't
2. Typosquatting            — lookalike domain (amaz0n.com, paypa1.com)
3. Subdomain Trap           — brand name buried before an unrelated root domain
4. Urgency / Time Pressure  — "act now", "24 hours", "final notice"
5. Fear / Authority         — threats, impersonating IT/law enforcement/C-suite
6. Financial Bait           — wire transfers, gift cards, billing updates
7. Sensitive Info Requests  — asks for passwords, OTPs, MFA codes
8. Raw IP Address Link      — http://12.34.56.78/... instead of a domain
9. URL Shortener            — bit.ly / tinyurl hiding the real destination
10. Anchor Text Mismatch    — link text says one thing, href goes elsewhere
11. Dangerous Attachment    — .exe, .scr, .js, .iso, .hta, .docm, etc.
12. Double Extension        — invoice.pdf.exe
13. Generic Greeting        — "Dear Customer" instead of your name

Golden rule: PAUSE -> VERIFY (via a separate known channel) -> REPORT.
""")


def main() -> None:
    print("=" * 70)
    print("  DECODELABS | Cyber Security Project 3")
    print("  Phishing Awareness Analysis — Triage Tool")
    print("=" * 70)

    menu = """
Choose an option:
  1) Analyze a built-in sample message
  2) Analyze your own message
  3) View red-flag reference guide
  4) Exit
> """

    while True:
        choice = input(menu).strip()

        if choice == "1":
            print("\nSample messages:")
            print("  1) Fake Microsoft account alert (malicious)")
            print("  2) Fake CEO wire-transfer request (malicious)")
            print("  3) Legitimate internal project update (safe)")
            print("  4) Fake ChatGPT billing update (malicious)")
            pick = input("Pick a sample (1-4): ").strip()
            email = SAMPLES.get(pick)
            if email:
                print_report(email)
            else:
                print("  Invalid sample number.")

        elif choice == "2":
            email = build_email_from_input()
            print_report(email)

        elif choice == "3":
            show_red_flag_reference()

        elif choice == "4":
            print("Session complete. Threat identified. Badge earned. 🛡")
            break

        else:
            print("  Invalid choice — please enter 1, 2, 3, or 4.")


if __name__ == "__main__":
    main()
