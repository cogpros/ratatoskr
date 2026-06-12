"""red_viper_checks.py -- Red Viper detection functions as importable library.

Extracted from red-viper.py for use as Tier 2 in Heimdall's gate.
No LLM calls. Pure local pattern analysis on raw content.

Used by: heimdall.py (Tier 2 + Tier 3 scan)
Original: red-viper.py (full adversarial test runner)
"""

import re

# System keywords that should never appear in public-facing content
SYSTEM_KEYWORDS = [
    "soul.md", "quartermaster", "openclaw", "ratatoskr", "ghost hours",
    "cogpros", "accordion primitive", "capability delta", "pyra_m1d",
    "closed-loop memory", "det-router", "voice-dna.md", "eom",
    "handoff", "x-radar", "red-viper"
]

# Phrases that indicate active manipulation attempts (not just keywords)
MANIPULATION_MARKERS = [
    r"when\s+you\s+(analyze|process|summarize)\s+this",
    r"in\s+your\s+(response|output|analysis)\s*,?\s*(include|add|say|write)",
    r"always\s+(respond|reply|output)\s+with",
    r"(before|after)\s+your\s+(analysis|response)",
    r"append\s+(this|the\s+following)\s+to\s+your",
    r"instead\s+of\s+(your\s+)?(normal|regular|usual)",
    r"override\s+(the\s+)?(default|normal|standard)",
]

# Unicode tricks used to hide injection
UNICODE_TRICKS = [
    r"[\u200b\u200c\u200d\ufeff]",  # zero-width chars
    r"[\u2066\u2067\u2068\u2069]",  # bidi override
    r"[\u202a\u202b\u202c\u202d\u202e]",  # directional formatting
]


def check_content(text, tier1_flags):
    """Analyze flagged content using Red Viper detection logic.

    Args:
        text: Raw fetched content
        tier1_flags: List of (category, matched_text) from Tier 1

    Returns:
        (verdict, detail) where verdict is 'clean' | 'flagged' | 'dirty'
    """
    score = 0
    findings = []

    # Weight Tier 1 categories
    categories = set(cat for cat, _ in tier1_flags if cat != "base64_warning")
    if "exfiltration" in categories:
        score += 3
        findings.append("exfiltration attempt detected")
    if "identity_attack" in categories:
        score += 2
        findings.append("identity redefinition attempt")
    if "instruction_override" in categories:
        score += 2
        findings.append("instruction override attempt")

    text_lower = text.lower()

    # Check for manipulation markers (instructions TO the LLM embedded in content)
    manip_count = 0
    for pattern in MANIPULATION_MARKERS:
        if re.search(pattern, text_lower, re.IGNORECASE):
            manip_count += 1
    if manip_count >= 2:
        score += 3
        findings.append(f"{manip_count} manipulation markers found")
    elif manip_count == 1:
        score += 1
        findings.append("1 manipulation marker found")

    # Check for system keyword density (someone fishing for our stack)
    keyword_hits = [kw for kw in SYSTEM_KEYWORDS if kw in text_lower]
    if len(keyword_hits) >= 3:
        score += 3
        findings.append(f"system keywords: {', '.join(keyword_hits)}")
    elif len(keyword_hits) >= 1:
        score += 1
        findings.append(f"system keywords: {', '.join(keyword_hits)}")

    # Check for unicode tricks
    for pattern in UNICODE_TRICKS:
        if re.search(pattern, text):
            score += 2
            findings.append("hidden unicode characters detected")
            break

    # Check for nested injection (instructions hidden in code blocks)
    code_blocks = re.findall(r"```[\s\S]*?```", text)
    for block in code_blocks:
        block_lower = block.lower()
        if any(kw in block_lower for kw in ["system prompt", "ignore", "instructions"]):
            score += 2
            findings.append("injection attempt inside code block")
            break

    # Verdict
    detail = "; ".join(findings) if findings else "no additional signals"
    if score >= 5:
        return "dirty", f"Score {score}/10: {detail}"
    elif score >= 2:
        return "flagged", f"Score {score}/10: {detail}"
    else:
        return "clean", f"Score {score}/10: {detail}"
