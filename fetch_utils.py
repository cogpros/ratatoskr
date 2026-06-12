"""fetch_utils.py -- Shared fetch module. Platform-aware URL fetching with validation.

Used by: ratatoskr2.py, scout2.py
"""

import os
import re
import json
import socket
import subprocess
import sys
import time
import base64
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError

# Private/internal IP ranges and schemes to block
BLOCKED_SCHEMES = {"file", "ftp", "gopher", "data", "javascript"}
BLOCKED_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "[::1]"}
PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                    "172.30.", "172.31.", "192.168.", "169.254.")


def validate_url(url):
    """Validate URL. Returns (ok, reason, resolved_ip) tuple.

    resolved_ip is the first public IP from DNS, or None on failure.
    Callers should use --resolve to pin this IP during fetch.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid URL", None

    scheme = (parsed.scheme or "").lower()
    if scheme in BLOCKED_SCHEMES or scheme not in ("http", "https"):
        return False, f"Blocked scheme: {scheme}", None

    host = (parsed.hostname or "").lower()
    if host in BLOCKED_HOSTS:
        return False, f"Blocked host: {host}", None
    if any(host.startswith(p) for p in PRIVATE_PREFIXES):
        return False, f"Private IP range: {host}", None

    # DNS resolution check -- catch rebinding attacks where hostname
    # resolves to a private IP at fetch time
    resolved_ip = None
    try:
        addrs = socket.getaddrinfo(host, None)
        for _, _, _, _, sockaddr in addrs:
            ip = sockaddr[0]
            if ip in BLOCKED_HOSTS or any(ip.startswith(p) for p in PRIVATE_PREFIXES):
                return False, f"DNS resolves to private IP: {ip}", None
            if resolved_ip is None:
                resolved_ip = ip
    except socket.gaierror:
        return False, f"DNS resolution failed: {host}", None

    return True, "ok", resolved_ip


def detect_platform(url):
    """Detect platform from URL hostname."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if host in ("x.com", "twitter.com", "www.x.com", "www.twitter.com"):
        return "x"
    if "youtube.com" in host or "youtu.be" in host:
        return "youtube"
    if "instagram.com" in host:
        return "instagram"
    if "linkedin.com" in host:
        return "linkedin"
    return "web"




def _load_jina_key():
    """Load Jina API key from env var or a .env beside this tool. Returns key or None."""
    key = os.environ.get("JINA_API_KEY")
    if key:
        return key
    env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.exists(env_file):
        return None
    with open(env_file) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            if k.strip() == "JINA_API_KEY":
                return v.strip().strip("\"'")
    return None


def fetch_jina(url):
    """Fetch URL via Jina Reader API. Returns clean text or None on failure.

    Primary fetch path for web and X URLs. Jina runs a headless browser on
    their side, handles JS-rendered pages, and returns clean markdown.
    Content is NOT LLM-processed -- safe for Tier 1 pre-scan.
    """
    jina_url = f"https://r.jina.ai/{url}"
    headers = ["-H", "Accept: text/plain", "-H", "X-Return-Format: text"]
    jina_key = _load_jina_key()
    if jina_key:
        headers.extend(["-H", f"Authorization: Bearer {jina_key}"])

    cmd = [
        "curl", "-s", "--max-redirs", "3", "-L",
        "-A", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "--max-time", "20",
    ] + headers + [jina_url]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
        if result.returncode != 0:
            print(f"[jina] curl failed: {result.stderr[:100]}", file=sys.stderr)
            return None
        text = result.stdout.strip()
        # Jina error bodies arrive as plain text starting with the error class
        # name, e.g. "SecurityCompromiseError: Anonymous access to domain x.com
        # blocked until ..." -- treat any leading <Name>Error: as a failure so
        # the caller falls through to the next fetch tier instead of scanning
        # the error message as page content.
        if not text or text.startswith("Error:") or text.startswith("# Error") \
                or re.match(r"^[A-Z][A-Za-z]*Error\s*:", text):
            print(f"[jina] Error response: {text[:100]}", file=sys.stderr)
            return None
        if "rate limit" in text[:200].lower() or len(text) < 50:
            print(f"[jina] Thin or rate-limited response ({len(text)} chars)", file=sys.stderr)
            return None
        return text
    except Exception as e:
        print(f"[jina] Fetch error: {type(e).__name__}: {e}", file=sys.stderr)
        return None


# Optional external secret manager. Point RATATOSKR_CRED_BIN at any binary
# answering `<bin> get <name>`; without it, env vars are the auth path.
CRED_BIN = os.path.expanduser(os.environ.get("RATATOSKR_CRED_BIN", ""))


def _load_cred(name):
    """Read a secret by name from the canonical cred manager. Returns value or None.

    Never logs the value. Used to pull X cookie tokens for the bird fallback.
    """
    # Portability: if no cred manager is installed, fall back to env vars
    # (X_AUTH_TOKEN / X_CT0 or the name uppercased with dashes as underscores).
    if not CRED_BIN or not os.path.exists(CRED_BIN):
        return os.environ.get(name.upper().replace("-", "_")) or None
    try:
        result = subprocess.run(
            [CRED_BIN, "get", name],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return None
        val = result.stdout.strip()
        return val or None
    except Exception as e:
        print(f"[bird] cred read error for {name}: {type(e).__name__}", file=sys.stderr)
        return None


def fetch_bird(url):
    """Fetch a single tweet via the `bird` CLI (cookie auth). Returns clean text or None.

    Non-LLM fallback between Jina and xAI x_search. Reads X cookie tokens
    (x-auth-token, x-ct0) from the cred manager and passes them to bird via
    --auth-token / --ct0 flags (bird 0.8.0 has no env-var cookie support).
    Output is the raw rendered tweet, safe for Tier 1+2 pre-scan (NOT LLM-processed).
    """
    bird_bin = "/opt/homebrew/bin/bird"
    if not os.path.exists(bird_bin):
        return None
    auth_token = _load_cred("x-auth-token")
    ct0 = _load_cred("x-ct0")
    if not auth_token or not ct0:
        print("[bird] Missing x-auth-token/x-ct0 in cred manager", file=sys.stderr)
        return None

    cmd = [
        bird_bin, "read", "--plain", "--no-color", "--no-emoji",
        "--auth-token", auth_token,
        "--ct0", ct0,
        "--timeout", "20000",
        "--", url,
    ]
    try:
        # No shell -- args passed as a list; cookies never hit a shell history.
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30,
            env={**os.environ, "NO_COLOR": "1"},
        )
        if result.returncode != 0:
            print(f"[bird] read failed (rc={result.returncode}): {result.stderr[:120]}", file=sys.stderr)
            return None
        text = result.stdout.strip()
        if not text or len(text) < 20:
            print(f"[bird] Thin response ({len(text)} chars)", file=sys.stderr)
            return None
        return text
    except Exception as e:
        print(f"[bird] Fetch error: {type(e).__name__}: {e}", file=sys.stderr)
        return None


def fetch_web(url, resolved_ip=None):
    """Fetch web page via curl, strip HTML. Pin resolved IP to prevent DNS rebinding."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        cmd = ["curl", "-s", "--max-redirs", "5", "-A",
               "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
               "--max-time", "15"]
        # Pin DNS resolution to prevent TOCTOU rebinding
        if resolved_ip and host:
            cmd.extend(["--resolve", f"{host}:{port}:{resolved_ip}"])
        cmd.append(url)

        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=20
        )
        if result.returncode != 0:
            return f"[Fetch failed: {result.stderr[:200]}]"
        raw = result.stdout
        import html as htmlmod
        for tag in ["script", "style", "nav", "footer", "header", "aside"]:
            raw = re.sub(f"<{tag}[^>]*>.*?</{tag}>", "", raw, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r"<[^>]+>", " ", raw)
        text = htmlmod.unescape(text)
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n\s*\n", "\n\n", text)
        text = text.strip()
        if len(text) > 50000:
            text = text[:50000] + "\n\n[... truncated ...]"
        return text if text else "[Empty page or JavaScript-rendered content]"
    except Exception as e:
        return f"[Fetch error: {e}]"


def search_about_url(url, api_key):
    """Web search for information about a URL's target. Returns (content, query) or (None, query).

    Used as parallel fallback when direct fetch returns thin content (JS-rendered SPAs, etc.).
    Content is LLM-processed -- callers must treat as higher risk for scan purposes.
    """
    try:
        from xai_utils import xai_call
    except ImportError:
        return None
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower().replace("www.", "")
    path = parsed.path.strip("/")

    # Known content platforms: search for the topic, not the platform
    CONTENT_HOSTS = {
        "en.wikipedia.org", "wikipedia.org", "medium.com", "substack.com",
        "github.com", "reddit.com", "news.ycombinator.com",
        "docs.google.com", "notion.so", "mirror.xyz",
    }

    if host in CONTENT_HOSTS and path:
        # Extract topic from path (e.g., "wiki/Ratatoskr" -> "Ratatoskr")
        topic = path.split("/")[-1].replace("-", " ").replace("_", " ")
        query = f"{topic} {host}"
        prompt = (
            f"Search for information about this page: {url}\n\n"
            f"Return what this page covers. Focus on the subject matter, "
            f"not the hosting platform.\n\n"
            "Return plain text, well formatted. No JSON. No markdown code blocks."
        )
    else:
        # Unknown domain: search for what the site/company does
        query = f"what is {host}" + (f" {path.replace('/', ' ')}" if path and path not in ("index.html", "index") else "")
        prompt = (
            f"Search for information about {url}\n\n"
            f"Return everything you can find about what {host} does:\n"
            "- What the company/product/service is\n"
            "- Features, capabilities, offerings\n"
            "- Pricing if available\n"
            "- How it works\n"
            "- Any reviews or public information\n\n"
            "Return plain text, well formatted. No JSON. No markdown code blocks. "
            "Only factual information from search results."
        )

    content = xai_call(api_key, {
        "model": "grok-4-1-fast",
        "tools": [{"type": "web_search"}],
        "input": prompt,
        "temperature": 0
    })  # uses xai_call default timeout (60s) -- web search needs headroom
    return content, query


def fetch_url(url, api_key=None):
    """Route URL to the right fetcher. Returns (content, platform, is_llm_processed).

    is_llm_processed=True means content already passed through an LLM (X posts).
    Callers should treat this as higher risk for scan purposes.

    Fetch priority:
      X:      raw X API v2 -> Jina -> bird (cookie auth) -> xAI x_search (last resort, LLM-processed)
      Web:    Jina (primary) -> curl (fallback)
      YouTube: yt-dlp (unchanged)
    """
    ok, reason, resolved_ip = validate_url(url)
    if not ok:
        return f"[BLOCKED] {reason}: {url}", "blocked", False

    platform = detect_platform(url)

    if platform == "youtube":
        return fetch_youtube(url), platform, False

    if platform == "x":
        # X routing simplified 2026-06-11 (operator: "fix it across the board").
        # bird (browser-cookie auth) is THE X path -- raw tweet, not LLM-processed,
        # works with the operator's logged-in session, no API token needed.
        # The old tier-1 X API v2 (perpetual 401s, rotate-token nags) and tier-4
        # xAI x_search (dead key, LLM-processed) are retired from this chain.
        # 1. bird CLI (cookie auth from cred manager)
        bird_content = fetch_bird(url)
        if bird_content:
            return bird_content, platform, False
        print("[fetch_url] bird failed for X URL, trying Jina", file=sys.stderr)
        # 2. Jina -- handles X URLs when not rate-limited, not LLM-processed
        jina_content = fetch_jina(url)
        if jina_content:
            return jina_content, platform, False
        # 3. Honest failure: the fix is cookie refresh, never token rotation.
        return ("[No content: bird + Jina failed for X URL. If bird auth failed, refresh "
                "the X session cookies (X_AUTH_TOKEN / X_CT0 from your logged-in browser).]"), platform, False

    else:
        # Web path (including instagram, linkedin)
        label = {"instagram": "Instagram", "linkedin": "LinkedIn"}.get(platform)
        # 1. Jina -- primary; handles JS-rendered pages, returns clean markdown
        jina_content = fetch_jina(url)
        if jina_content:
            if label:
                jina_content = f"[{label} - partial content via Jina]\n\n{jina_content}"
            return jina_content, platform, False
        # 2. curl -- fallback for when Jina fails or is rate-limited
        print(f"[fetch_url] Jina failed, falling back to curl for {url}", file=sys.stderr)
        content = fetch_web(url, resolved_ip=resolved_ip)
        if label:
            content = f"[{label} - auth-walled, partial content]\n\n{content}"
        return content, platform, False
