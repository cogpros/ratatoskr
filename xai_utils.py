"""xai_utils.py -- xAI API client for Ratatoskr.

Handles API calls to xAI (Grok) for summarization and web search.
API key loaded from XAI_API_KEY env var or ~/.ratatoskr/api-key file.
"""

import json
import os
import re
import subprocess
import sys

KEY_FILE = os.path.expanduser("~/.ratatoskr/api-key")


def load_xai_key():
    """Load xAI API key. Checks env var first, then key file."""
    key = os.environ.get("XAI_API_KEY")
    if key:
        return key
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE) as f:
            return f.read().strip()
    return None


def xai_call(api_key, payload, timeout=60):
    """Make xAI API call via curl. Routes to Responses API when tools are present."""
    use_responses = "tools" in payload
    endpoint = "https://api.x.ai/v1/responses" if use_responses else "https://api.x.ai/v1/chat/completions"

    if use_responses:
        # Responses API expects 'input' not 'messages'
        if "messages" in payload and "input" not in payload:
            msgs = payload.pop("messages")
            payload["input"] = msgs[-1]["content"] if len(msgs) == 1 else msgs

    try:
        result = subprocess.run(
            [
                "curl", "-s", "--max-time", str(timeout),
                "-X", "POST", endpoint,
                "-H", f"Authorization: Bearer {api_key}",
                "-H", "Content-Type: application/json",
                "-d", json.dumps(payload),
            ],
            capture_output=True, text=True, timeout=timeout + 5,
        )
        data = json.loads(result.stdout)

        if use_responses:
            for item in data.get("output", []):
                if item.get("type") == "message":
                    for content in item.get("content", []):
                        if content.get("type") == "output_text":
                            return content["text"]
        else:
            return data["choices"][0]["message"]["content"]
    except Exception as e:
        print(f"[xai_call error] {type(e).__name__}: {e}", file=sys.stderr)
    return None


def parse_xai_json(raw):
    """Parse JSON from xAI output, stripping markdown code block wrappers."""
    if not raw:
        return None
    text = raw.strip()
    text = re.sub(r'^```(?:json)?\s*', '', text)
    text = re.sub(r'\s*```$', '', text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None
