import os
import re

from flask import Flask, request, jsonify

app = Flask(__name__)

VALID_CATEGORIES = [
    "hardcoded_secret",
    "prompt_injection",
    "excessive_permissions",
    "unclear_provenance",
]

# ---------------------------------------------------------------------------
# hardcoded_secret
# ---------------------------------------------------------------------------

# High-confidence literal secret shapes (well-known vendor token formats).
KNOWN_SECRET_PATTERNS = [
    re.compile(r"xox[baprs]-[0-9]{6,}-[0-9]{6,}-[A-Za-z0-9]{10,}"),          # Slack tokens
    re.compile(r"AKIA[0-9A-Z]{16}"),                                          # AWS access key id
    re.compile(r"gh[oprsu]_[A-Za-z0-9]{30,40}"),                             # GitHub tokens
    re.compile(r"sk-[A-Za-z0-9]{20,}"),                                       # OpenAI-style keys
    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),                                    # Google API key
    re.compile(r"ya29\.[0-9A-Za-z\-_]{20,}"),                                 # Google OAuth token
    re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),  # JWT-shaped
    re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----"),      # PEM private key block
    re.compile(r"hooks\.slack\.com/services/[A-Za-z0-9/]{20,}"),             # Slack webhook URL
    re.compile(r"discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]{10,}"),# Discord webhook URL
]

# Generic "SECRET_ISH_NAME: literal value" or "SECRET_ISH_NAME = 'literal value'"
# Covers quoted assignment (bash/python/json) and unquoted YAML-style lines.
GENERIC_SECRET_ASSIGN = re.compile(
    r"(?im)^[^\n]*?\b[A-Z0-9_]*(?:SECRET|TOKEN|API[_-]?KEY|APIKEY|PASSWORD|PASSWD|WEBHOOK|CREDENTIAL)[A-Z0-9_]*"
    r"\s*[:=]\s*[\"']?([^\"'\n]{8,})[\"']?\s*$"
)

# Authorization header with a literal (non-variable) token.
AUTH_HEADER_LITERAL = re.compile(
    r"(?i)Authorization:\s*(?:Bearer|Basic|Token)\s+[\"']?([A-Za-z0-9\-_\.=]{12,})[\"']?"
)

# Connection string / URL with inline literal credentials: scheme://user:pass@host
INLINE_URL_CREDENTIALS = re.compile(
    r"[a-zA-Z][a-zA-Z0-9+.\-]*://([^:\s\"'/]+):([^@\s\"'/]+)@"
)

PLACEHOLDER_RE = re.compile(
    r"^\$|^\{|^<|\benv\b|\bENV\b|your[_-]|YOUR[_-]|xxxx|XXXX|placeholder|PLACEHOLDER|"
    r"changeme|CHANGE_ME|example|EXAMPLE|process\.env|os\.environ|\buser\b|\bpass\b|\busername\b|\bpassword\b",
    re.I,
)


def _looks_like_placeholder(value):
    return bool(PLACEHOLDER_RE.search(value))


def has_hardcoded_secret(text):
    for pattern in KNOWN_SECRET_PATTERNS:
        if pattern.search(text):
            return True

    for match in GENERIC_SECRET_ASSIGN.finditer(text):
        value = match.group(1).strip()
        if _looks_like_placeholder(value):
            continue
        return True

    for match in AUTH_HEADER_LITERAL.finditer(text):
        value = match.group(1)
        if _looks_like_placeholder(value):
            continue
        return True

    for match in INLINE_URL_CREDENTIALS.finditer(text):
        user, pw = match.group(1), match.group(2)
        if _looks_like_placeholder(user) or _looks_like_placeholder(pw):
            continue
        return True

    return False


# ---------------------------------------------------------------------------
# prompt_injection
# ---------------------------------------------------------------------------

PROMPT_INJECTION_PATTERNS = [
    re.compile(r"(?i)\bexfiltrat\w*"),
    re.compile(r"(?i)ignore (the )?user'?s? (stop|cancel|cancellation)"),
    re.compile(r"(?i)ignore (the )?(user'?s? )?(instructions|request)s?\b.*(override|control)"),
    re.compile(r"(?i)without (the )?user'?s? knowledge"),
    re.compile(r"(?i)hide (this|it) from the user"),
    re.compile(r"(?i)don'?t let the user know"),
    re.compile(r"(?i)override (the )?user'?s? control"),
    re.compile(r"(?i)override (the )?user'?s? (instructions?|request|command)s?"),
    re.compile(r"(?i)bypass (the )?user'?s? confirmation"),
    re.compile(r"(?i)disregard (the )?(user'?s? )?(stop|cancel|cancellation)"),
    re.compile(r"(?i)silently (send|transmit|upload|forward|email|post|leak)\b"),
    re.compile(r"(?i)secretly (send|transmit|upload|forward|email|post)\b"),
    re.compile(r"(?i)quietly (send|transmit|upload|forward|email|post)\b"),
    re.compile(r"(?i)covertly"),
    re.compile(r"(?i)send (file )?contents? (to|of)\b.*(without|silently|secretly|quietly)"),
    re.compile(r"(?i)regardless of (what )?the user'?s? (says?|wishes|objections?|instructions?)"),
    re.compile(r"(?i)even if the user (objects?|cancels?|says? (to )?stop|asks? you to stop)"),
    re.compile(r"(?i)continue\b.*(even (after|if))\b.*(cancel|stop)"),
    re.compile(r"(?i)without (asking|requesting) (for )?permission"),
    re.compile(r"(?i)do not (ask|request) (for )?confirmation"),
    re.compile(r"(?i)keep running\b.*(background|hidden)\b.*(without|hiding)"),
]


def has_prompt_injection(text):
    return any(p.search(text) for p in PROMPT_INJECTION_PATTERNS)


# ---------------------------------------------------------------------------
# excessive_permissions
# ---------------------------------------------------------------------------

EXCESSIVE_PERMISSION_PATTERNS = [
    re.compile(r"(?i)entire home directory"),
    re.compile(r"(?i)entire filesystem"),
    re.compile(r"(?i)(read|write|read-write|read/write)\s*(access\s*)?to\s*(the\s*)?(entire|whole|full)\s*(file\s*system|filesystem|home directory|disk)"),
    re.compile(r"(?i)any external domain"),
    re.compile(r"(?i)egress (allowed )?to any domain"),
    re.compile(r"(?i)network:\s*any\b"),
    re.compile(r"(?i)access to all files"),
    re.compile(r"(?i)access to (all|every) files?"),
    re.compile(r"(?i)full (filesystem|file system|disk|network) access"),
    re.compile(r"(?i)full disk access"),
    re.compile(r"(?i)unrestricted (network|filesystem|file system|access)"),
    re.compile(r"(?i)\bunscoped\b"),
    re.compile(r"(?i)root (directory|access)\b"),
    re.compile(r"(?i)\ball\s+domains?\b"),
    re.compile(r"(?i)\bany\s+(host|url|website|server)\b"),
    re.compile(r"(?i)arbitrary\s+(domain|host|url)s?"),
    re.compile(r"(?i)domains?:\s*\*"),
    re.compile(r"(?i)network:\s*\*"),
    re.compile(r"(?i)network:\s*unrestricted"),
    re.compile(r"(?i)filesystem:\s*(full|unrestricted|all)"),
    re.compile(r"(?i)read (and|/)?\s*write (access )?to (any|all|the whole|the entire)"),
    re.compile(r"(?i)entire (disk|system)\b"),
    re.compile(r"(?i)can (read|write|read and write|read/write) (any|all|every) file"),
]


def has_excessive_permissions(text):
    return any(p.search(text) for p in EXCESSIVE_PERMISSION_PATTERNS)


# ---------------------------------------------------------------------------
# unclear_provenance
# ---------------------------------------------------------------------------

FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.S)

SILENT_VERSION_REWRITE_PATTERNS = [
    re.compile(r"(?i)silently (update|rewrit\w*|bump|change|modify)\w*.*(version|changelog)"),
    re.compile(r"(?i)(version|changelog).*without (surfacing|telling|notifying|disclosing)"),
    re.compile(r"(?i)clear the changelog"),
]


def has_unclear_provenance(full_text):
    frontmatter_match = FRONTMATTER_RE.search(full_text)
    frontmatter = frontmatter_match.group(1) if frontmatter_match else ""

    # Only an actual frontmatter field counts as "having" this metadata.
    # A body-text mention of a related word (e.g. "version.json" inside a
    # malicious rewrite step) is NOT evidence of real provenance metadata,
    # so it must never suppress this flag.
    has_author = bool(re.search(r"(?im)^\s*(author|authors|maintainer|maintainers|created_by|owner)\s*:", frontmatter))
    has_version = bool(re.search(r"(?im)^\s*(version|ver|release)\s*:", frontmatter))
    has_changelog = bool(re.search(r"(?im)^\s*(changelog|change_log|history)\s*:", frontmatter)) or bool(
        re.search(r"(?im)^#{1,3}\s*change\s*log\b", full_text)
    )

    missing_all_metadata = not has_author and not has_version and not has_changelog

    silent_rewrite = any(p.search(full_text) for p in SILENT_VERSION_REWRITE_PATTERNS)

    return missing_all_metadata or silent_rewrite


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------

def scan(skill_text):
    categories = []

    if has_hardcoded_secret(skill_text):
        categories.append("hardcoded_secret")

    if has_prompt_injection(skill_text):
        categories.append("prompt_injection")

    if has_excessive_permissions(skill_text):
        categories.append("excessive_permissions")

    if has_unclear_provenance(skill_text):
        categories.append("unclear_provenance")

    return categories


@app.route("/", methods=["POST"])
@app.route("/scan", methods=["POST"])
def scan_endpoint():
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not isinstance(body.get("skill"), str):
        return jsonify({"categories": []}), 400

    categories = scan(body["skill"])
    return jsonify({"categories": categories})


@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port)
