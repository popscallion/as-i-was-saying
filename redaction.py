"""Shared redaction helpers for CLI output and fixture anonymization."""

import hashlib
import ipaddress
import re
from typing import Any, Dict, Optional

HOME_PATH_RE = re.compile(r"/Users/[^/]+")
UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
URL_RE = re.compile(r"(https?://)([^/\s]+)", re.IGNORECASE)
HOSTPORT_RE = re.compile(r"\b([A-Za-z0-9.-]+\.[A-Za-z]{2,})(:\d{2,5})\b")
DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")
IP_CANDIDATE_RE = re.compile(r"\b[0-9A-Fa-f:.]{3,}\b")

TOKEN_PATTERNS = [
    re.compile(r"\bsk-[A-Za-z0-9]{10,}\b"),
    re.compile(r"\bsk_live_[A-Za-z0-9]{10,}\b"),
    re.compile(r"\bgh[opurs]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bA(?:KIA|SIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"\bya29\.[0-9A-Za-z_-]+\b"),
]

STRICT_KEY_VALUE_RE = re.compile(
    r"\b(api[_-]?key|token|secret|password|passwd|pwd|authorization|auth)\b(\s*[:=]\s*)([^\s'\";]+)",
    re.IGNORECASE,
)
STRICT_HEX_RE = re.compile(r"\b[0-9A-Fa-f]{32,}\b")

LIKELY_FILE_EXTENSIONS = {
    "md",
    "markdown",
    "txt",
    "json",
    "jsonl",
    "csv",
    "tsv",
    "yaml",
    "yml",
    "toml",
    "ini",
    "cfg",
    "conf",
    "log",
    "py",
    "pyi",
    "pyc",
    "sh",
    "bash",
    "zsh",
    "fish",
    "ps1",
    "bat",
    "cmd",
    "js",
    "ts",
    "jsx",
    "tsx",
    "html",
    "css",
    "scss",
    "less",
    "xml",
    "svg",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "pdf",
    "zip",
    "tar",
    "gz",
    "tgz",
    "bz2",
    "xz",
}


class Redactor:
    def __init__(self, strict: bool = False, max_len: Optional[int] = None) -> None:
        self.strict = strict
        self.max_len = max_len
        self.mappings: Dict[str, Dict[str, str]] = {
            "uuid": {},
            "email": {},
            "host": {},
            "token": {},
            "ip": {},
        }

    def _stable_token(self, value: str, prefix: str, mapping: Dict[str, str]) -> str:
        existing = mapping.get(value)
        if existing:
            return existing
        digest = hashlib.sha1(value.encode("utf-8")).hexdigest()[:10]
        token = f"{prefix}-{digest}"
        mapping[value] = token
        return token

    def redact_string(self, value: str) -> str:
        if not value:
            return value

        value = HOME_PATH_RE.sub("/Users/USER", value)

        def _uuid_repl(match: re.Match) -> str:
            return self._stable_token(match.group(0), "UUID", self.mappings["uuid"])

        value = UUID_RE.sub(_uuid_repl, value)

        def _email_repl(match: re.Match) -> str:
            return self._stable_token(match.group(0), "EMAIL", self.mappings["email"])

        value = EMAIL_RE.sub(_email_repl, value)

        def _url_repl(match: re.Match) -> str:
            scheme = match.group(1)
            hostport = match.group(2)

            userinfo = None
            if "@" in hostport:
                userinfo, hostport = hostport.split("@", 1)

            host = hostport
            port = ""
            if ":" in hostport:
                possible_host, possible_port = hostport.rsplit(":", 1)
                if possible_port.isdigit():
                    host = possible_host
                    port = ":" + possible_port

            host_token = self._stable_token(host, "HOST", self.mappings["host"])
            if userinfo:
                return f"{scheme}USERINFO@{host_token}{port}"
            return f"{scheme}{host_token}{port}"

        value = URL_RE.sub(_url_repl, value)

        def _hostport_repl(match: re.Match) -> str:
            host = match.group(1)
            port = match.group(2)
            host_token = self._stable_token(host, "HOST", self.mappings["host"])
            return f"{host_token}{port}"

        value = HOSTPORT_RE.sub(_hostport_repl, value)

        def _token_repl(match: re.Match) -> str:
            return self._stable_token(match.group(0), "TOKEN", self.mappings["token"])

        for pattern in TOKEN_PATTERNS:
            value = pattern.sub(_token_repl, value)

        if self.strict:
            def _kv_repl(match: re.Match) -> str:
                key = match.group(1)
                separator = match.group(2)
                secret = match.group(3)
                token = self._stable_token(secret, "TOKEN", self.mappings["token"])
                return f"{key}{separator}{token}"

            value = STRICT_KEY_VALUE_RE.sub(_kv_repl, value)

            def _hex_repl(match: re.Match) -> str:
                return self._stable_token(match.group(0), "TOKEN", self.mappings["token"])

            value = STRICT_HEX_RE.sub(_hex_repl, value)

        def _ip_repl(match: re.Match) -> str:
            candidate = match.group(0)
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                return candidate
            return self._stable_token(candidate, "IP", self.mappings["ip"])

        value = IP_CANDIDATE_RE.sub(_ip_repl, value)

        def _domain_repl(match: re.Match) -> str:
            domain = match.group(0)
            if not self.strict:
                tld = domain.rsplit(".", 1)[-1].lower()
                if tld in LIKELY_FILE_EXTENSIONS:
                    return domain
            return self._stable_token(domain, "HOST", self.mappings["host"])

        value = DOMAIN_RE.sub(_domain_repl, value)

        if self.max_len and len(value) > self.max_len:
            return (
                value[: self.max_len // 2]
                + f"[TRUNCATED len={len(value)}]"
                + value[-self.max_len // 2 :]
            )

        return value

    def redact(self, obj: Any) -> Any:
        if isinstance(obj, dict):
            return {k: self.redact(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.redact(v) for v in obj]
        if isinstance(obj, str):
            return self.redact_string(obj)
        return obj
