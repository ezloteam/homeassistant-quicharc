"""Strip secrets and personal data from text before it leaves the home.

Architecture section 10.5: no tokens, keys, cookies, passwords or grant
bodies; IP addresses cut to the /24 (IPv4) or /48 (IPv6) network.
Ezlo user, home and device ids are allowed. Email addresses are removed too.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Final

_PATTERNS: Final[list[tuple[re.Pattern[str], str]]] = [
    # JSON Web Tokens (Ezlo access and id tokens).
    (
        re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"),
        "<jwt>",
    ),
    # cloud/login refresh tokens.
    (re.compile(r"ezlo_rt_[A-Za-z0-9_-]+"), "<refresh token>"),
    (re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]+"), r"\1<token>"),
    # key=value, key: value and 'key': 'value' for secret-bearing keys.
    (
        re.compile(
            r"(?i)\b(access_token|refresh_token|id_token|token|credential|password"
            r"|code_verifier|code|grant|proof|cookie|secret)"
            r"""(['"]?\s*[:=]\s*['"]?)[^\s'",&}]+"""
        ),
        r"\1\2<redacted>",
    ),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "<email>"),
    (re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}\b"), r"\1.0"),
]


# Anything shaped like an IPv6 address; only real ones are rewritten.
_IPV6_CANDIDATE: Final = re.compile(
    r"(?<![\w:])[0-9A-Fa-f:]*:[0-9A-Fa-f:]*:[0-9A-Fa-f:]*(?![\w:])"
)


def _ipv6_network(match: re.Match[str]) -> str:
    try:
        address = ipaddress.IPv6Address(match[0])
    except ValueError:
        return match[0]
    return str(ipaddress.IPv6Network(f"{address}/48", strict=False).network_address)


def scrub(text: str) -> str:
    """Return text with tokens, secrets, emails and full IP addresses removed."""
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return _IPV6_CANDIDATE.sub(_ipv6_network, text)
