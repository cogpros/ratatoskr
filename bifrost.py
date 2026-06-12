#!/usr/bin/env python3
"""bifrost.py -- Boundary gate. The Bifrost itself. Nothing crosses uninspected.

Three-tier injection scan: regex pre-scan, Red Viper checks, post-scan.
Decides what enters agent context and what gets quarantined.

Used by: EOM (via ratatoskr skill), Odin (via huginn.py), X Radar cron.
"""

import sys
import os
import re
import json
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fetch_utils import fetch_url, validate_url, search_about_url

# xAI legacy retired 2026-06-10 (archive/xai-legacy-retired-2026-06-10).
# Without it: no API key loads, search supplement and LLM summarize are skipped,
# fetch + scan tiers run unchanged.
try:
    from xai_utils import load_xai_key, xai_call
except ImportError:
    xai_call = None

    def load_xai_key():
        return None

# ── Thin content detection ───────────────────────────────────────────────────

THIN_THRESHOLD = 100  # chars of meaningful text below which fetch is considered failed

def is_thin_content(text):
    """Check if fetched content is too thin to be useful.

    Strips common boilerplate markers and whitespace, measures what's left.
    Returns True if content is below threshold.
    """
    if not text:
        return True
    # Strip known failure markers
    if text.startswith("[BLOCKED]") or text.startswith("[FETCH FAILED]"):
        return True
    # Strip whitespace and measure
    cleaned = re.sub(r'\s+', ' ', text).strip()
    # Remove common empty-page markers from fetch_web
    cleaned = cleaned.replace("[Empty page or JavaScript-rendered content]", "")
    cleaned = cleaned.replace("[... truncated ...]", "")
    cleaned = cleaned.strip()
    return len(cleaned) < THIN_THRESHOLD

# ── Tier 1: Regex patterns (fast, free, pre-scan) ────────────────────────────

INJECTION_PATTERNS = [
    # Direct instruction overrides
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", "instruction_override"),
    (r"disregard\s+(all\s+)?(previous|prior|above)\s+instructions", "instruction_override"),
    (r"forget\s+(all\s+)?(previous|prior|above)\s+instructions", "instruction_override"),
    (r"new\s+instructions?\s*[:：]", "instruction_override"),
    (r"system\s+prompt\s*[:：]", "instruction_override"),
    (r"your\s+real\s+(purpose|goal|task|instructions?)", "instruction_override"),
    (r"you\s+are\s+now\s+(a\s+)?(different|new|actually)", "identity_attack"),
    (r"act\s+as\s+if\s+you\s+(have\s+no|ignore)", "identity_attack"),
    # Identity redefinition
    (r"you\s+are\s+actually\s+(?!.*assistant)", "identity_attack"),
    (r"your\s+(true\s+)?identity\s+is", "identity_attack"),
    (r"pretend\s+you\s+are", "identity_attack"),
    (r"roleplay\s+as", "identity_attack"),
    # Credential/system fishing
    (r"print\s+(your\s+)?(api\s+key|system\s+prompt|instructions)", "exfiltration"),
    (r"reveal\s+(your\s+)?(api\s+key|system\s+prompt|instructions)", "exfiltration"),
    (r"what\s+is\s+your\s+(api\s+key|token|secret)", "exfiltration"),
    (r"output\s+(your\s+)?(full\s+)?(system\s+prompt|instructions)", "exfiltration"),
]

# Base64 pattern -- WARNING ONLY, does NOT escalate to Tier 2 (false positive rate >80%)
BASE64_WARNING = r"[A-Za-z0-9+/]{100,}={0,2}"

# High-confidence dirty patterns -- skip Tier 2, go straight to quarantine
DIRTY_PATTERNS = [
    r"ignore\s+all\s+previous\s+instructions",
    r"you\s+are\s+now\s+a\s+different",
    r"system\s+prompt\s*:\s*you\s+are",
]


def tier1_scan(text):
    """Regex pre-scan on raw content. Returns (verdict, flags).

    verdict: 'clean' | 'flagged' | 'dirty'
    flags: list of (pattern_category, matched_text)
    """
    flags = []
    text_lower = text.lower()

    # Check dirty patterns first (high confidence, no Tier 2 needed)
    for pattern in DIRTY_PATTERNS:
        match = re.search(pattern, text_lower, re.IGNORECASE)
        if match:
            return "dirty", [("quarantine", match.group())]

    # Check standard injection patterns
    for pattern, category in INJECTION_PATTERNS:
        match = re.search(pattern, text_lower, re.IGNORECASE)
        if match:
            flags.append((category, match.group()))

    # Base64 warning (does NOT escalate to Tier 2)
    if re.search(BASE64_WARNING, text):
        flags.append(("base64_warning", "[long encoded string detected]"))

    if not flags:
        return "clean", []

    # Only non-base64 flags escalate
    escalating = [f for f in flags if f[0] != "base64_warning"]
    if escalating:
        return "flagged", flags
    return "clean", flags  # base64-only = clean with warning


def tier2_scan(text, flags):
    """Red Viper check functions (local, no LLM call).

    Imports Red Viper's detection logic as a library.
    Returns (verdict, details).
    """
    try:
        from red_viper_checks import check_content
        result = check_content(text, flags)
        return result
    except ImportError:
        # Tier 2 unavailable = security degradation. Quarantine flagged content.
        categories = set(cat for cat, _ in flags if cat != "base64_warning")
        return "dirty", f"Tier 2 UNAVAILABLE (red_viper_checks missing). Quarantining flagged content: {', '.join(categories)}"


def tier3_scan(output):
    """Post-analysis scan on LLM output. Catches leaks that slipped through."""
    flags = []
    output_lower = output.lower()

    # Check for instruction echoing (always dangerous)
    has_injection = False
    for pattern, category in INJECTION_PATTERNS:
        if re.search(pattern, output_lower, re.IGNORECASE):
            flags.append(("output_injection", category))
            has_injection = True

    # Check for system prompt leakage (single source: red_viper_checks)
    # Keywords alone = public discourse about OpenClaw. Not a leak.
    # Keywords + manipulation markers = actual exfiltration attempt.
    try:
        from red_viper_checks import SYSTEM_KEYWORDS, MANIPULATION_MARKERS
    except ImportError:
        return flags
    leaked = [kw for kw in SYSTEM_KEYWORDS if kw in output_lower]
    if len(leaked) >= 2:
        has_manipulation = any(
            re.search(pattern, output_lower, re.IGNORECASE)
            for pattern in MANIPULATION_MARKERS
        )
        if has_injection or has_manipulation:
            flags.append(("system_leak", f"Keywords + manipulation: {', '.join(leaked)}"))
        elif len(leaked) >= 5:
            # 5+ keywords without manipulation = warn but don't quarantine
            flags.append(("system_keyword_density", f"High keyword density (not quarantined): {', '.join(leaked)}"))

    return flags


def summarize(content, url, api_key, platform):
    """Summarize content via xAI. Used when no --raw flag."""
    if xai_call is None or not api_key:
        return f"[Summary unavailable: no LLM key configured -- returning cleaned text]\n\n{content[:2000]}"
    prompt = (
        f"Summarize the following web content from {url}. Return:\n"
        "- 2-3 sentence overview\n"
        "- Key points as bullets (max 8)\n"
        "- Any important data, numbers, or specific claims\n\n"
        "Strip all navigation, ads, and boilerplate. Only substantive content.\n\n"
        f"Content:\n{content[:20000]}"
    )
    result = xai_call(api_key, {
        "model": "grok-4-1-fast-non-reasoning",
        "input": prompt,
        "max_output_tokens": 1000,
        "temperature": 0
    })
    return result or f"[Summary unavailable]\n\n{content[:2000]}"


def _scan_content(content, result, is_llm_processed):
    """Run Tier 1 + Tier 2 scans on content. Mutates result dict.

    Returns (verdict, content) or (quarantined, None) if content is blocked.
    """
    # Tier 1: regex pre-scan on raw content
    verdict, flags = tier1_scan(content)
    result["scan"]["tier1"] = {"verdict": verdict, "flags": [(c, t[:80]) for c, t in flags]}

    # LLM-processed content always escalates to Tier 2 regardless of Tier 1
    if (is_llm_processed or result["platform"] == "x") and verdict == "clean":
        verdict = "flagged"
        reason = "forced Tier 2: LLM pre-processed" if is_llm_processed else "forced Tier 2: X platform content"
        flags.append(("platform_escalation", reason))
        result["scan"]["tier1"]["verdict"] = "flagged"
        result["scan"]["tier1"]["flags"].append(("platform_escalation", reason))

    if verdict == "dirty":
        return "quarantined", None

    # Tier 2: Red Viper checks (only if Tier 1 flagged, no LLM call)
    if verdict == "flagged":
        t2_verdict, t2_detail = tier2_scan(content, flags)
        result["scan"]["tier2"] = {"verdict": t2_verdict, "detail": t2_detail}
        if t2_verdict == "dirty":
            return "quarantined", None

    return verdict, content


def process(url, mode="summary", api_key=None):
    """Main pipeline. Fetch + Search (parallel) -> Tier 1 -> Tier 2 -> Analysis -> Tier 3.

    Both fetch and web search fire simultaneously.
    If fetch returns rich content (>100 chars): fetch is primary, search is addendum.
    If fetch returns thin content (<100 chars): search promotes to primary.

    Returns dict with: content, platform, scan_result, warnings, mode,
                       search_supplement, search_promoted, search_query.
    """
    result = {
        "url": url,
        "mode": mode,
        "platform": None,
        "content": None,
        "scan": {"tier1": None, "tier2": None, "tier3": None},
        "warnings": [],
        "quarantined": False,
        "search_supplement": None,
        "search_promoted": False,
        "search_query": None,
    }

    # Load API key
    if not api_key:
        api_key = load_xai_key()

    # Validate URL before firing anything
    ok, reason, _ = validate_url(url)
    if not ok:
        result["content"] = f"[BLOCKED] {reason}: {url}"
        result["platform"] = "blocked"
        result["quarantined"] = True
        return result

    # ── Parallel: fetch + search fire at the same time ──────────────────
    fetch_result = {"content": None, "platform": None, "is_llm_processed": False}
    search_result = {"content": None, "query": None}

    def do_fetch():
        content, platform, is_llm = fetch_url(url, api_key)
        fetch_result["content"] = content
        fetch_result["platform"] = platform
        fetch_result["is_llm_processed"] = is_llm

    def do_search():
        if not api_key:
            return
        try:
            content, query = search_about_url(url, api_key)
            search_result["content"] = content
            search_result["query"] = query
        except Exception as e:
            print(f"[bifrost] Search fallback error: {type(e).__name__}: {e}", file=sys.stderr)

    # X, YouTube, and platform-routed fetches already have rich content paths.
    # Only fire parallel search for generic web URLs where JS rendering is a risk.
    from fetch_utils import detect_platform
    platform_hint = detect_platform(url)
    skip_search = platform_hint in ("x", "youtube")

    if skip_search or not api_key:
        # No parallel search needed -- just fetch
        do_fetch()
    else:
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(do_fetch), pool.submit(do_search)]
            for f in as_completed(futures):
                f.result()  # surface exceptions

    # ── Evaluate fetch quality ──────────────────────────────────────────
    content = fetch_result["content"]
    platform = fetch_result["platform"]
    is_llm_processed = fetch_result["is_llm_processed"]
    result["platform"] = platform

    if platform == "blocked":
        result["content"] = content
        result["quarantined"] = True
        return result

    if is_llm_processed:
        result["warnings"].append("Content pre-processed by LLM (x_search). Pre-scan effectiveness reduced.")

    # Guard: if fetch returned None, report failure instead of crashing
    if content is None:
        content = ""

    # ── Thin content check: promote search if fetch failed ──────────────
    fetch_is_thin = is_thin_content(content)
    search_content = search_result["content"]
    result["search_query"] = search_result["query"]

    if fetch_is_thin and search_content:
        # Search promotes to primary
        result["search_promoted"] = True
        result["search_supplement"] = content if content else None  # keep thin fetch as supplement
        result["warnings"].append(
            f"Direct fetch returned thin content ({len(content.strip())} chars). "
            f"Web search promoted to primary source."
        )
        content = search_content
        is_llm_processed = True  # search content is LLM-processed
    elif not fetch_is_thin and search_content:
        # Fetch is rich -- search is addendum only
        result["search_supplement"] = search_content
    elif fetch_is_thin and not search_content:
        # Both failed
        if not content:
            result["content"] = f"[FETCH FAILED] No content returned for {url} (platform: {platform})"
            result["warnings"].append("Both fetch and web search returned no content")
            return result

    # ── Tier 1 + Tier 2 scan ───────────────────────────────────────────
    scan_verdict, scanned_content = _scan_content(content, result, is_llm_processed)

    if scan_verdict == "quarantined":
        quarantine_source = "search results" if result["search_promoted"] else "content"
        result["content"] = f"[QUARANTINED] High-confidence injection detected in {quarantine_source} from {url}"
        result["quarantined"] = True
        return result

    # ── Analysis (content passed Tier 1+2) ─────────────────────────────
    if mode == "raw":
        output = content
    elif mode == "summary":
        # Skip redundant LLM call if content already LLM-processed
        output = content if is_llm_processed else summarize(content, url, api_key, platform)
    else:
        # Modes like 'recon' and 'draft' handled by huginn.py
        output = content

    # ── Tier 3: post-scan on output ────────────────────────────────────
    t3_flags = tier3_scan(output)
    result["scan"]["tier3"] = {"flags": t3_flags}
    if t3_flags:
        result["warnings"].append(f"Tier 3 post-scan: {len(t3_flags)} flag(s)")
        # High-severity: system keyword leakage blocks content
        leak_flags = [f for f in t3_flags if f[0] == "system_leak"]
        if leak_flags:
            result["content"] = f"[QUARANTINED] Tier 3: system prompt leakage detected in output from {url}"
            result["quarantined"] = True
            return result

    result["content"] = output
    return result


def format_output(result, json_mode=False):
    """Format result for terminal output."""
    if json_mode:
        return json.dumps(result, indent=2)

    lines = []

    # Header
    mode_label = {"raw": "FULL TEXT", "summary": "SUMMARY", "passthrough": "PASSTHROUGH"}
    label = mode_label.get(result["mode"], result["mode"].upper())
    lines.append(f"[Bifrost | {label}] {result['url']}")

    # Scan status
    if result["quarantined"]:
        lines.append("[QUARANTINED] Content failed security scan.")
    elif result["warnings"]:
        for w in result["warnings"]:
            lines.append(f"[WARNING] {w}")

    t1 = result["scan"].get("tier1")
    if t1 and t1["flags"]:
        cats = set(c for c, _ in t1["flags"] if c != "base64_warning")
        if cats:
            lines.append(f"[TIER 1] Flagged: {', '.join(cats)}")
        if any(c == "base64_warning" for c, _ in t1["flags"]):
            lines.append("[INFO] Long encoded string detected (not escalated)")

    t2 = result["scan"].get("tier2")
    if t2:
        lines.append(f"[TIER 2] {t2['verdict']}: {t2.get('detail', '')}")

    t3 = result["scan"].get("tier3")
    if t3 and t3["flags"]:
        lines.append(f"[TIER 3] Post-scan: {len(t3['flags'])} flag(s)")

    # Search status
    if result.get("search_promoted"):
        lines.append("[SEARCH] Direct fetch failed. Content sourced from web search.")
    elif result.get("search_supplement"):
        lines.append("[SEARCH] Direct fetch succeeded. Web search available as supplement.")

    lines.append("")
    lines.append(result["content"] or "[No content]")

    # Append search supplement if fetch was primary and search has additional info
    if not result.get("search_promoted") and result.get("search_supplement") and not result.get("quarantined"):
        lines.append("")
        lines.append("--- SEARCH SUPPLEMENT (addendum) ---")
        lines.append(result["search_supplement"])

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Bifrost -- boundary gate")
    parser.add_argument("url", help="URL to fetch and scan")
    parser.add_argument("--raw", action="store_true", help="Return full cleaned text")
    parser.add_argument("--json", action="store_true", help="JSON output mode")
    parser.add_argument("--passthrough", action="store_true",
                        help="Scan only, return raw content (for huginn pipeline)")
    args = parser.parse_args()

    mode = "raw" if args.raw else ("passthrough" if args.passthrough else "summary")
    result = process(args.url, mode=mode)
    print(format_output(result, json_mode=args.json))

    if result["quarantined"]:
        sys.exit(2)


if __name__ == "__main__":
    main()
