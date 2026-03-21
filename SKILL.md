---
name: ratatoskr
description: "Fetch any external URL safely into agent context. Parallel fetch + web search, three-tier injection scan, JS-rendered page fallback. Use instead of raw WebFetch for untrusted URLs."
version: "1.0.0"
author: "Dustin Pollock <dustin@ravenai.ca>"
license: "MIT"
tags: ["security", "fetch", "web", "injection-defense"]
---

# Ratatoskr

Ratatoskr runs between worlds. It carries content from the open web into your context without becoming part of it.

Raw page content, potential injection attempts, and unknown payloads stay outside. Only content that passes the gate crosses back.

## Usage

```
/ratatoskr <url>
/ratatoskr <url> --raw
/ratatoskr <url> --json
```

- **Default:** Returns a structured summary. Key points, headings, substance. Injection surface minimized.
- **`--raw`:** Returns full cleaned text. More fidelity, more surface. Use when you need the complete content.
- **`--json`:** Returns structured JSON with scan results, warnings, and content.

## The Pipeline

Ratatoskr (fetch) + Web Search (parallel) -> Heimdall (gate) -> context.

1. Receives the URL and flags
2. Validates URL (blocks file://, localhost, private IPs, DNS rebinding)
3. **Two paths fire in parallel:**
   - **Ratatoskr** fetches via platform-aware routing (`fetch_utils.py`)
   - **Web search** queries xAI with `web_search` tool for info about the target
4. **Heimdall evaluates fetch quality:**
   - If fetch returns rich content (100+ chars): fetch is primary, search is addendum
   - If fetch returns thin content (<100 chars): search promotes to primary
5. **Heimdall** runs Tier 1 regex pre-scan on the primary content
6. **Heimdall** runs Tier 2 pattern checks if Tier 1 flags (or if content is LLM-processed)
7. Summarizes (default), returns raw text (--raw), or passes through (--passthrough)
8. **Heimdall** runs Tier 3 post-scan on output for system prompt leakage
9. Returns clean output with search supplement, or quarantined result

Search is skipped for X and YouTube URLs (those platforms already have dedicated rich-content paths).

## What It Protects Against

- Prompt injection buried in webpage content
- Instruction override attempts in articles or docs
- Identity redefinition attempts targeting the receiving agent
- Credential or system info exfiltration via crafted content
- Silent manipulation of agent behavior through untrusted text

## What It Does Not Protect Against

- Content you paste directly into chat (different path, not fetched live)
- Content already in your memory files
- Zero-day injection patterns not covered by the scan heuristics

## Setup

### 1. Install the skill

Copy this directory into your Claude Code skills folder:

```bash
cp -r ratatoskr ~/.claude/skills/ratatoskr
```

### 2. Set your xAI API key

The web search fallback and summarization require an xAI API key. Either:

```bash
# Option A: environment variable
export XAI_API_KEY="your-key-here"

# Option B: key file
mkdir -p ~/.ratatoskr
echo "your-key-here" > ~/.ratatoskr/api-key
chmod 600 ~/.ratatoskr/api-key
```

Without an API key, Ratatoskr still works for direct web fetches (curl + HTML strip) and YouTube (yt-dlp). You lose: web search fallback, X post fetching, and LLM summarization.

### 3. Optional: yt-dlp for YouTube

```bash
brew install yt-dlp   # macOS
# or: pip install yt-dlp
```

## How to Execute

When `/ratatoskr <url>` is invoked, run heimdall.py directly:

```bash
python3 /path/to/ratatoskr/heimdall.py "<url>"           # summary (default)
python3 /path/to/ratatoskr/heimdall.py "<url>" --raw     # full cleaned text
python3 /path/to/ratatoskr/heimdall.py "<url>" --json    # structured JSON
```

Heimdall IS the pipeline entry point. It calls fetch_utils.py internally, runs all scan tiers, and returns clean output.

## Scripts

- **Pipeline entry point:** `heimdall.py` (CLI with argparse)
- **Fetch routing:** `fetch_utils.py` (platform detection, curl, yt-dlp, xAI x_search)
- **Scan patterns:** `red_viper_checks.py` (Tier 2 pattern analysis)
- **API client:** `xai_utils.py` (xAI/Grok API calls)

## Routing

- **X/Twitter URLs:** Routes through xAI x_search. Content is LLM-processed, so Tier 2 always runs. No parallel search (already rich).
- **YouTube URLs:** Routes through yt-dlp for metadata. No parallel search (already rich).
- **All other URLs:** Direct fetch (curl + HTML strip) runs in parallel with web search. If curl gets real content, it leads. If the site is JS-rendered and curl gets nothing, search fills the gap.
- **Auth-walled URLs** (Google Docs, Confluence, etc.): Will fail gracefully with a clear error.
- **Known content platforms** (Wikipedia, Medium, GitHub, Reddit, etc.): Search query targets the page topic, not the hosting platform.

## Customization

### System keywords (red_viper_checks.py)

The `SYSTEM_KEYWORDS` list in `red_viper_checks.py` defines what Tier 3 considers a system prompt leak. The default list is generic. Replace it with keywords specific to your agent's identity, tools, and configuration.

### Thin content threshold (heimdall.py)

`THIN_THRESHOLD = 100` controls when search promotes to primary. Lower it if you want search to kick in less often. Raise it if you want more aggressive fallback.

## The Names

**Ratatoskr** is the squirrel that runs up and down Yggdrasil carrying messages between the eagle at the crown and the dragon at the roots. It fetches.

**Heimdall** stands on the Bifrost. He sees everything that approaches. He decides what crosses. He gates.
