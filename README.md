# Password Strength Checker

A resume-ready cyber security mini-project that analyzes a password using practical rules inspired by real-world attack patterns.

## What this tool checks

1. **Length**
   - Flags short passwords and rates length quality (`Too short`, `Minimum`, `Good`, `Excellent`).
2. **Character diversity**
   - Checks for uppercase, lowercase, digits, and special characters.
3. **Common word detection**
   - Detects common words and exact weak-password matches (e.g., `password123`).
4. **Breach-based pattern detection**
   - Detects repeated characters, common sequences (`1234`, `qwerty`, `abcd`), year-like patterns, and low-uniqueness passwords.

## How scoring works

The checker builds a score from:
- length compliance
- character diversity (0–4 points)
- penalties for common words/exact weak passwords
- penalties for breach-like patterns

Final rating:
- **Strong**
- **Moderate**
- **Weak**
- **Very Weak**

## Run locally

```bash
python app.py
```

Then enter a password when prompted.

## Example

```text
Enter a password to assess: P@ssword2024!!!

Password Analysis for: P@ssword2024!!!
-------------------------------------------------------
Length: 15 (Good)

Character Diversity:
- Uppercase letter present: Yes
- Lowercase letter present: Yes
- Number present: Yes
- Special character present: Yes
- Diversity score: 4/4

Common Word Detection:
- Contains common words: Yes
- Words found: password
- Exact common password match: No

Breach-Based Pattern Detection:
- Breach patterns detected: Yes
  • Repeated characters (e.g., aaa, 111)

Overall Password Strength: Weak (score: 2)
```

## Why this looks good on a resume

- Shows secure coding and validation logic.
- Demonstrates understanding of password attack heuristics.
- Easy to extend with API-driven breach checks (e.g., Have I Been Pwned k-anonymity model).
