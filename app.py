import re
from typing import Dict, List

COMMON_PASSWORDS = {
    "password",
    "password123",
    "123456",
    "12345678",
    "qwerty",
    "abc123",
    "admin",
    "letmein",
    "welcome",
    "iloveyou",
}

COMMON_WORDS = {
    "password",
    "admin",
    "welcome",
    "login",
    "user",
    "company",
    "security",
    "cyber",
    "default",
}


def normalized(password: str) -> str:
    """Normalize a password for dictionary checks."""
    replacements = str.maketrans({"@": "a", "$": "s", "0": "o", "1": "l", "3": "e", "5": "s", "7": "t"})
    return password.lower().translate(replacements)


def analyze_length(password: str) -> Dict[str, object]:
    length = len(password)
    if length >= 16:
        rating = "Excellent"
    elif length >= 12:
        rating = "Good"
    elif length >= 8:
        rating = "Minimum"
    else:
        rating = "Too short"

    return {
        "length": length,
        "length_rating": rating,
        "length_ok": length >= 8,
    }


def analyze_character_diversity(password: str) -> Dict[str, object]:
    checks = {
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "lowercase": bool(re.search(r"[a-z]", password)),
        "number": bool(re.search(r"\d", password)),
        "special_char": bool(re.search(r"[^A-Za-z0-9]", password)),
    }
    diversity_score = sum(checks.values())

    return {
        **checks,
        "diversity_score": diversity_score,
    }


def detect_common_words(password: str) -> Dict[str, object]:
    candidate = normalized(password)
    found_words = [word for word in COMMON_WORDS if word in candidate]
    exact_common_password = candidate in COMMON_PASSWORDS

    return {
        "contains_common_word": bool(found_words),
        "common_words_found": sorted(found_words),
        "exact_common_password": exact_common_password,
    }


def detect_breach_patterns(password: str) -> Dict[str, object]:
    patterns: List[str] = []
    candidate = normalized(password)

    if re.search(r"(.)\1{2,}", password):
        patterns.append("Repeated characters (e.g., aaa, 111)")

    if candidate.isdigit() and (candidate in {"123456", "12345678", "123456789"}):
        patterns.append("Common numeric password sequence")

    if any(seq in candidate for seq in ["1234", "2345", "abcd", "qwerty"]):
        patterns.append("Keyboard/alphabetical sequence")

    if re.search(r"(19|20)\d{2}", candidate):
        patterns.append("Contains year-like pattern")

    if len(set(password)) <= max(2, len(password) // 4):
        patterns.append("Low character uniqueness")

    return {
        "breach_patterns_found": patterns,
        "has_breach_pattern": bool(patterns),
    }


def assess_password_strength(password: str) -> Dict[str, object]:
    length = analyze_length(password)
    diversity = analyze_character_diversity(password)
    common_words = detect_common_words(password)
    breach_patterns = detect_breach_patterns(password)

    score = 0
    score += 1 if length["length"] >= 8 else 0
    score += diversity["diversity_score"]  # up to 4
    score -= 1 if common_words["contains_common_word"] else 0
    score -= 2 if common_words["exact_common_password"] else 0
    score -= 2 if breach_patterns["has_breach_pattern"] else 0

    if score >= 5 and not breach_patterns["has_breach_pattern"] and not common_words["exact_common_password"]:
        strength = "Strong"
    elif score >= 3:
        strength = "Moderate"
    elif score >= 1:
        strength = "Weak"
    else:
        strength = "Very Weak"

    return {
        "password": password,
        **length,
        **diversity,
        **common_words,
        **breach_patterns,
        "strength": strength,
        "score": score,
    }


def display_password_strength(password_assessment: Dict[str, object]) -> None:
    print(f"\nPassword Analysis for: {password_assessment['password']}")
    print("-" * 55)
    print(f"Length: {password_assessment['length']} ({password_assessment['length_rating']})")

    print("\nCharacter Diversity:")
    print(f"- Uppercase letter present: {'Yes' if password_assessment['uppercase'] else 'No'}")
    print(f"- Lowercase letter present: {'Yes' if password_assessment['lowercase'] else 'No'}")
    print(f"- Number present: {'Yes' if password_assessment['number'] else 'No'}")
    print(f"- Special character present: {'Yes' if password_assessment['special_char'] else 'No'}")
    print(f"- Diversity score: {password_assessment['diversity_score']}/4")

    print("\nCommon Word Detection:")
    print(f"- Contains common words: {'Yes' if password_assessment['contains_common_word'] else 'No'}")
    if password_assessment["common_words_found"]:
        print(f"- Words found: {', '.join(password_assessment['common_words_found'])}")
    print(f"- Exact common password match: {'Yes' if password_assessment['exact_common_password'] else 'No'}")

    print("\nBreach-Based Pattern Detection:")
    print(f"- Breach patterns detected: {'Yes' if password_assessment['has_breach_pattern'] else 'No'}")
    for pattern in password_assessment["breach_patterns_found"]:
        print(f"  • {pattern}")

    print(f"\nOverall Password Strength: {password_assessment['strength']} (score: {password_assessment['score']})")


def main() -> None:
    password = input("Enter a password to assess: ")
    assessment = assess_password_strength(password)
    display_password_strength(assessment)


if __name__ == "__main__":
    main()
