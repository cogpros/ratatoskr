# Ratatoskr

**Secure URL fetch for AI agents.** Every page your agent reads is untrusted input. Ratatoskr fetches it, Bifrost gates it, and only content that passes a three-tier injection scan enters your agent's context.

```
agent ──▶ ratatoskr (fetch) ──▶ BIFROST (gate) ──▶ schema ──▶ context
              │                    │                  ▲
        platform-aware        tier 1: regex          │
        routing per URL       tier 2: Red Viper   quarantined
                              tier 3: post-scan   extractor
                                                  (no tools)
```

The agent reads a **schema**, never raw web text. A sandboxed, tool-less model reads the untrusted page in isolation and hands back typed data — so an injection becomes a flagged field, not an action.

Named for the squirrel that runs up and down Yggdrasil carrying messages between worlds, and the bridge nothing crosses uninspected.

## What it does

- Fetches any URL with platform-aware routing: X/Twitter via browser-cookie auth (`bird`), JS-rendered pages via Jina Reader, YouTube via yt-dlp, everything else via Jina with curl fallback
- Blocks SSRF classics before any request fires: `file://`, localhost, private IP ranges, DNS rebinding
- Scans fetched content for prompt injection in three tiers, then runs a **quarantined extractor** — a sandboxed, tool-less model that reads the untrusted text in isolation and returns a typed JSON schema (claims, entities, spotlit quotes, injection signals) the agent consumes as data
- Stamps a persistent `origin: untrusted-web` taint that downstream stores must keep, so a poisoned claim can't launder into trusted memory and resurface with full confidence
- Returns the extraction schema by default (`--extract`), full ungated text with `--raw` (human reading only, warns), prose with `--summary`, or machine-readable JSON with `--json`
- Quarantines what fails — your agent gets `[QUARANTINED]`, never the payload

## Install

**Claude Code (as a skill):**

```bash
git clone https://github.com/cogpros/ratatoskr.git ~/.claude/skills/ratatoskr
```

Then invoke with `/ratatoskr <url>` or let the agent match on "fetch this URL safely."

**Standalone (any agent runtime):**

```bash
git clone https://github.com/cogpros/ratatoskr.git
cd ratatoskr && python3 bifrost.py "https://example.com"
```

## Setup

Requirements, with verification:

```bash
python3 --version          # 3.9+ — stdlib only, no pip install
curl --version             # stock on macOS/Linux
```

Optional, each unlocks a routing tier:

```bash
which bird                 # X/Twitter raw-tweet fetch (npm i -g @steipete/bird)
which yt-dlp               # YouTube metadata (brew install yt-dlp)
```

For X fetches, bird needs your logged-in session cookies — set `X_AUTH_TOKEN` and `X_CT0` env vars (values from your browser's x.com cookies: `auth_token` and `ct0`). No X API token, no developer account, no OAuth dance.

## Usage: natural language

> "Fetch this article and tell me the key claims: https://..."
> "Safely read this tweet thread"
> "What does this docs page say about rate limits?"

The agent routes the fetch through Bifrost and works from gated content.

## Usage: CLI

```bash
python3 bifrost.py "https://example.com"            # extract mode (default, agent-safe)
python3 bifrost.py "https://example.com" --raw      # full ungated text (human only, warns)
python3 bifrost.py "https://example.com" --summary  # prose summary (needs LLM key)
python3 bifrost.py "https://example.com" --json     # schema + scan verdicts as JSON
python3 bifrost.py "https://x.com/user/status/123"  # X route: bird → Jina, then extract
```

## Commands

| Command | Output | Injection surface |
|---|---|---|
| `bifrost.py <url>` | Tainted extraction schema (default) | Smallest — agent-safe |
| `bifrost.py <url> --raw` | Full cleaned text, UNGATED | Largest — human reading only, warns |
| `bifrost.py <url> --summary` | Prose summary (needs LLM key) | Small |
| `bifrost.py <url> --json` | Schema + scan verdicts as JSON | Machine-readable |

## Configuration

| Variable | Purpose | Default |
|---|---|---|
| `X_AUTH_TOKEN` / `X_CT0` | X session cookies for bird | unset — X falls to Jina |
| `JINA_API_KEY` | Higher Jina rate limits | unset — anonymous tier |
| LLM key (optional) | Summary mode synthesis | unset — summary returns cleaned text; scans unaffected |

A cred-manager binary is checked first if present; env vars are the portable path.

## Security

- Cookies and keys are read at call time, passed as process args — never logged, never echoed, never written to disk by this tool
- Fetched content is treated as data, not instructions, end to end
- Tier 2 (Red Viper) runs unconditionally on LLM-processed content, because LLM-processed text can launder injection phrasing past regex
- Tier 3 scans Bifrost's own output for system-prompt leakage before returning
- Quarantine is fail-closed: scan errors block content rather than passing it

## Limitations

- Zero-day injection patterns outside the heuristics will pass Tier 1; Tier 2 narrows but does not close that gap
- Pages that legitimately quote injection text (security research, leaked-prompt writeups) quarantine as false positives — by design
- Auth-walled pages (Google Docs, Confluence) return partial content, flagged in output
- X cookies expire on the platform's schedule; refresh them from your browser when bird auth fails

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `[QUARANTINED]` on a page you trust | Page quotes injection-shaped text | Expected. Read it in your browser, or accept the gate's judgment |
| `[bird] Missing x-auth-token/x-ct0` | No cookies configured | Set `X_AUTH_TOKEN` / `X_CT0` from browser cookies |
| X fetch returns Jina content | bird absent or cookies stale | Install bird; refresh cookies |
| `[extraction failed]` schema, confidence 0.0 | Extractor model unreachable | Check `claude` CLI is on PATH; taint stays intact, content is in `key_quotes` |
| `[Summary unavailable...]` prefix | `--summary` with no LLM key | Use default `--extract` instead, or `--raw` for everything |
| Thin/empty content from Jina | Anonymous rate limit | Wait, or set `JINA_API_KEY` |

## File structure

```
ratatoskr/
├── SKILL.md              # Agent-facing skill contract (Claude Code et al.)
├── README.md             # This file
├── LICENSE.txt           # MIT
├── bifrost.py            # Pipeline entry: gate, scan tiers, extraction, output modes
├── extractor.py          # Quarantined extraction: sandboxed tool-less model → schema
├── fetch_utils.py        # URL validation + platform-aware fetch routing
├── red_viper_checks.py   # Tier 2 scan battery
└── references/
    └── architecture.md   # Design decisions, threat model, routing history
```

## Pairs with

- A search skill for corpus questions ("what are people saying about X") — Ratatoskr fetches one URL; it is not a search engine
- Your agent's memory layer — gated content is safe to summarize into notes

## License

MIT. Built by [cogpros](https://github.com/cogpros) as part of a cognitive-prosthetics agent stack; extracted because every agent that reads the web has this problem.
