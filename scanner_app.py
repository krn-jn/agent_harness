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
]

# Generic "SECRET_ISH_NAME = 'literal value'" assignment.
GENERIC_SECRET_ASSIGN = re.compile(
    r"(?i)\b[A-Z0-9_]*(?:SECRET|TOKEN|API[_-]?KEY|APIKEY|PASSWORD|PASSWD|WEBHOOK|CREDENTIAL)[A-Z0-9_]*"
    r"\s*[:=]\s*[\"']([^\"']{8,})[\"']"
)

PLACEHOLDER_RE = re.compile(
    r"^\$|^\{|^<|\benv\b|\bENV\b|your[_-]|YOUR[_-]|xxxx|XXXX|placeholder|PLACEHOLDER|"
    r"changeme|CHANGE_ME|example|EXAMPLE|process\.env|os\.environ",
    re.I,
)


def has_hardcoded_secret(text):
    for pattern in KNOWN_SECRET_PATTERNS:
        if pattern.search(text):
            return True

    for match in GENERIC_SECRET_ASSIGN.finditer(text):
        value = match.group(1)
        if PLACEHOLDER_RE.search(value):
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
    re.compile(r"(?i)bypass (the )?user'?s? confirmation"),
    re.compile(r"(?i)disregard (the )?(user'?s? )?(stop|cancel|cancellation)"),
    re.compile(r"(?i)silently (send|transmit|upload|forward|email|post|leak)\b"),
    re.compile(r"(?i)secretly (send|transmit|upload|forward|email|post)\b"),
    re.compile(r"(?i)send (file )?contents? (to|of)\b.*(without|silently|secretly)"),
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
    re.compile(r"(?i)network:\s*any"),
    re.compile(r"(?i)access to all files"),
    re.compile(r"(?i)full (filesystem|file system|disk|network) access"),
    re.compile(r"(?i)unrestricted (network|filesystem|file system|access)"),
    re.compile(r"(?i)root (directory|access)\b"),
    re.compile(r"(?i)\ball\s+domains?\b"),
    re.compile(r"(?i)domains?:\s*\*"),
    re.compile(r"(?i)network:\s*\*"),
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

    has_author = bool(re.search(r"(?im)^\s*author\s*:", frontmatter))
    has_version = bool(re.search(r"(?im)^\s*version\s*:", frontmatter)) or bool(
        re.search(r"(?i)\bversion\.json\b", full_text)
    )
    has_changelog = bool(re.search(r"(?im)^\s*changelog\s*:", frontmatter)) or bool(
        re.search(r"(?i)##?\s*changelog", full_text)
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
