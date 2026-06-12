---
name: ratatoskr
description: "Secure URL fetch for AI agents. Fetches any external URL through a three-tier injection scan (the Bifrost gate) before content enters agent context. Platform-aware routing — X via browser-cookie auth (bird), JS-rendered pages via Jina Reader, YouTube via yt-dlp. Use instead of raw WebFetch for untrusted URLs; not for content pasted directly into chat."
version: "2.0.0"
author: "Dustin Pollock <dustin@ravenai.ca>"
license: "MIT"
compatibility: "Claude Code, OpenClaw, any agent runtime that can shell out to python3"
tags: ["security", "fetch", "web", "injection-defense", "prompt-injection"]
---

# Ratatoskr

Ratatoskr runs between worlds. It carries content from the open web into your agent's context without becoming part of it -- and without letting the web become part of your agent.

Raw page content, injection attempts, and unknown payloads stay outside. Only content that passes the Bifrost gate crosses.

## Usage

```
/ratatoskr <url>            # structured summary (least injection surface)
/ratatoskr <url> --raw      # full cleaned text (more fidelity, more surface)
/ratatoskr <url> --json     # structured JSON: scan results, warnings, content
```

## How to execute

When invoked, run bifrost.py directly:

```bash
cd <skill-dir> && python3 bifrost.py "<url>"           # summary (default)
cd <skill-dir> && python3 bifrost.py "<url>" --raw     # full cleaned text
cd <skill-dir> && python3 bifrost.py "<url>" --json    # structured JSON
```

Bifrost is the pipeline entry point. It calls fetch_utils.py internally, runs all scan tiers, and returns clean output -- or a quarantine notice.

## The pipeline

1. Validates the URL (blocks file://, localhost, private IPs, DNS rebinding)
2. Fetches via platform-aware routing (see Routing below)
3. Tier 1: regex pre-scan for high-confidence injection patterns
4. Tier 2: Red Viper checks when Tier 1 flags, or when content is LLM-processed
5. Summarize (default) / raw / JSON output
6. Tier 3: post-scan on output for system-prompt leakage

A page that fails the scan returns `[QUARANTINED]`, not content. That is the gate doing its job -- pages that quote prompt-injection text (security writeups, leaked system prompts) will quarantine even when benign. Use a search-engine summary for those.

## Routing

- **X/Twitter:** `bird` CLI with browser session cookies (raw tweet text, not LLM-processed), Jina Reader as fallback. No X API token needed, ever. Cookies come from a cred manager or `X_AUTH_TOKEN` / `X_CT0` env vars.
- **YouTube:** yt-dlp metadata.
- **Everything else:** Jina Reader (handles JS-rendered pages), direct curl as fallback.

## What it protects against

- Prompt injection buried in webpage content
- Instruction-override and identity-redefinition attempts in fetched text
- Credential or system-info exfiltration via crafted content
- Silent behavior manipulation through untrusted text

## NOT for

- Content the user pasted directly into chat (different trust path -- never fetched)
- Content already in your memory files
- Corpus-wide social search ("what are people saying about X") -- that is a research tool's job; Ratatoskr fetches one URL

## Known limitations

- Zero-day injection patterns outside the scan heuristics
- Auth-walled pages return partial content (noted in output)
- Without an LLM key, summary mode returns cleaned text instead of a summary -- fetch and scan tiers run unchanged

## The names

**Ratatoskr** is the squirrel that runs up and down Yggdrasil carrying messages between the eagle at the crown and the dragon at the roots. It fetches.

**Bifrost** is the only bridge between worlds. Nothing approaches uninspected. Nothing crosses unchecked. The bridge IS the gate.
