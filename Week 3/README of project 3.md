# Cyber Security — Project 3: Phishing Awareness Analysis

Industrial Training Kit · DecodeLabs · 2026 Batch

A command-line **phishing triage tool** that analyzes sample emails or
messages, flags social-engineering red flags, and explains why a
message is unsafe — mirroring the Pause → Verify → Report workflow and
the Safe / Suspicious / Malicious decision tree from the training kit.

This tool is defensive and educational only. It never sends mail,
clicks links, or executes attachments — it just reads text you give
it and reports on known indicators.

## What this project does

- **Identifies suspicious links or keywords** in a message
- **Lists red flags** found, each with a severity rating and plain-
  English explanation
- **Explains why the message is unsafe**, and gives a risk score
- **Classifies** the message as `SAFE`, `SUSPICIOUS`, or `MALICIOUS`
  and recommends an action (Close / Warn User / Block & Escalate)

## Files

| File                        | Purpose                                     |
|------------------------------|----------------------------------------------|
| `phishing_triage_tool.py`   | Full implementation + interactive CLI menu   |
| `README.md`                 | This file                                     |

## Requirements

- Python 3.9 or later (standard library only — no installs needed)

## How to run

```bash
python3 phishing_triage_tool.py
```

You'll see a menu:

```
Choose an option:
  1) Analyze a built-in sample message
  2) Analyze your own message
  3) View red-flag reference guide
  4) Exit
```

### Option 1 — Built-in samples
Four ready-made examples are included so you can see the tool in
action immediately:

1. Fake Microsoft account alert (malicious — spoofed domain + ISO attachment)
2. Fake CEO wire-transfer request (malicious — BEC / urgency / secrecy)
3. Legitimate internal project update (safe — no red flags)
4. Fake ChatGPT billing update (malicious — shortened link + mismatched anchor text)

### Option 2 — Analyze your own message
You'll be prompted for the sender's display name, email address,
subject, body (finish with a line containing only `END`), any
attachment filenames, and — optionally — the domain the message
*should* have come from. The tool then prints a full report.

### Option 3 — Red-flag reference guide
Prints the checklist of every indicator the tool looks for, useful as
a study sheet or as content for the "Red Flag Checklist" the kit's
conclusion slide suggests building.

### Example output

```
SUBJECT : FW: Urgent Your Account Security Alert
FROM    : Microsoft Support <support@logins-updates.com>
======================================================================
Red flags found (7):

  1. [★★★] Sender-Domain Mismatch
     -> Display name 'Microsoft Support' implies microsoft.com, but the
        message actually routes through 'logins-updates.com'.

  2. [★★★] Subdomain Trap
     -> Link buries 'microsoft' as a fake subdomain; the true root
        domain is 'logins-updates.com', not microsoft.com.

  ...

Risk Score : 16
Verdict    : MALICIOUS
Action     : Block & Escalate — report to security team immediately,
              do not click or reply.
```

## What it checks for

| # | Red flag | Severity |
|---|---|---|
| 1 | Sender-Domain Mismatch — display name says Brand X, routing domain doesn't | High |
| 2 | Typosquatting — lookalike domain within 1–2 character edits (`amaz0n.com`) | High |
| 3 | Subdomain Trap — brand name buried before an unrelated root domain | High |
| 4 | Urgency / Time Pressure — "act now", "24 hours", "final notice" | Medium |
| 5 | Fear / Authority Pressure — threats, impersonating IT/law enforcement/C-suite | High |
| 6 | Financial Bait — wire transfers, gift cards, billing updates | High |
| 7 | Sensitive Info Requests — asks for passwords, OTPs, MFA codes | High |
| 8 | Raw IP Address Link — `http://12.34.56.78/...` instead of a domain | High |
| 9 | URL Shortener — bit.ly/tinyurl hiding the real destination | Medium |
| 10 | Anchor Text / Destination Mismatch — link text says one thing, href goes elsewhere | High |
| 11 | Dangerous Attachment — `.exe .scr .js .iso .hta .docm` etc. | High |
| 12 | Double Extension — `invoice.pdf.exe` | Medium |
| 13 | Generic Greeting — "Dear Customer" instead of your name | Low |

## Scoring & classification

Each detected red flag carries a severity weight (Low = 1, Medium = 2,
High = 3). The total is summed into a risk score:

| Score | Verdict | Recommended action |
|---|---|---|
| 0 | SAFE | Close — no action needed |
| 1–3 | SUSPICIOUS | Warn User — verify via a separate, known channel before acting |
| 4+ | MALICIOUS | Block & Escalate — report to security immediately, do not click or reply |

This directly implements the triage decision tree from the training
kit (`Incoming Suspicious Email → Safe/Suspicious/Malicious → Close/
Warn User/Block & Escalate`).

## Design notes

- **Domain extraction** pulls the domain out of an email address or
  URL; **`registrable_root()`** naively takes the last two labels to
  demonstrate the "read URLs right to left" lesson from the kit. It's
  intentionally simple for teaching purposes — a production tool
  would use a real public-suffix-list parser (e.g. Python's `tldextract`)
  to handle multi-part TLDs like `.co.uk` correctly.
- **Typosquatting detection** uses Levenshtein (edit) distance against
  a small list of well-known brand domains.
- **Negation guard**: keyword matching strips a few common negated
  phrases (e.g. "non-urgent", "no action required") first, so a
  legitimate "Non-Urgent" email isn't flagged just for containing the
  substring "urgent".
- All detectors work on plain text you provide — no network calls,
  no attachment execution, no external services.

## Possible extensions

- Add a real public-suffix-list / `tldextract` dependency for
  accurate root-domain parsing
- Expand `KNOWN_BRAND_DOMAINS` with your organization's actual
  frequently-impersonated brands
- Add SPF/DKIM/DMARC header parsing if given raw `.eml` files
- Track results over time to build a "simulate → measure risk →
  deliver microlearning" reporting loop, as described in the kit
- Export reports as CSV/PDF for a security team dashboard

## Author

DecodeLabs Industrial Training Kit — Cyber Security Track, Project 3
