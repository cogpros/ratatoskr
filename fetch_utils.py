"""fetch_utils.py -- Platform-aware URL fetching with validation.

Fetches web content via curl, YouTube metadata via yt-dlp, X posts via xAI.
Includes URL validation (blocks private IPs, file:// scheme, DNS rebinding).
"""

import os
import re
import json
import socket
import subprocess
import sys
from urllib.parse import urlparse

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

    # DNS resolution check -- catch rebinding attacks
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


def fetch_x(url, api_key):
    """Fetch X post via xAI x_search. Returns LLM-processed text (not raw)."""
    from xai_utils import xai_call
    return xai_call(api_key, {
        "model": "grok-4-1-fast",
        "tools": [{"type": "x_search"}],
        "input": (
            f"Find and return the full content of this X post: {url}\n\n"
            "Return: author @handle, full post text, media descriptions, "
            "engagement (likes, reposts, bookmarks, views), posted date.\n"
            "Return plain text, well formatted. No JSON. No markdown code blocks."
        ),
        "temperature": 0
    })


def fetch_youtube(url):
    """Fetch YouTube video metadata via yt-dlp."""
    try:
        result = subprocess.run(
            ["yt-dlp", "--dump-json", "--no-download", "--", url],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return f"[YouTube fetch failed: {result.stderr[:200]}]"
        meta = json.loads(result.stdout)
        upload_date = meta.get("upload_date", "?")
        if upload_date and len(upload_date) == 8:
            upload_date = f"{upload_date[:4]}-{upload_date[4:6]}-{upload_date[6:]}"
        return (
            f"Channel: {meta.get('channel', '?')}\n"
            f"Title: {meta.get('title', '?')}\n"
            f"Duration: {meta.get('duration_string', '?')} | "
            f"Views: {meta.get('view_count', 0):,} | Uploaded: {upload_date}\n\n"
            f"Description:\n{meta.get('description', '')[:1000]}\n"
        )
    except Exception as e:
        return f"[YouTube fetch error: {e}]"


def fetch_web(url, resolved_ip=None):
    """Fetch web page via curl, strip HTML. Pin resolved IP to prevent DNS rebinding."""
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        cmd = ["curl", "-s", "--max-redirs", "0", "-A",
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
    from xai_utils import xai_call
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

    is_llm_processed=True means content already passed through an LLM.
    Callers should treat this as higher risk for scan purposes.
    """
    ok, reason, resolved_ip = validate_url(url)
    if not ok:
        return f"[BLOCKED] {reason}: {url}", "blocked", False

    platform = detect_platform(url)
    if platform == "x":
        if not api_key:
            return "[No xAI API key -- cannot fetch X posts]", platform, False
        content = fetch_x(url, api_key)
        return content, platform, True  # LLM-processed
    elif platform == "youtube":
        return fetch_youtube(url), platform, False
    else:
        label = {"instagram": "Instagram", "linkedin": "LinkedIn"}.get(platform)
        content = fetch_web(url, resolved_ip=resolved_ip)
        if label:
            content = f"[{label} - auth-walled, partial content]\n\n{content}"
        return content, platform, False
