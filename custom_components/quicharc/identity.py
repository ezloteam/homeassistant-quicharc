"""Who signed in: read claims from the tokens cloud/login returned.

The tokens come straight from cloud/login's token endpoint over TLS, and the
claims are only used to label the entry and to build key proofs. The
quicharc service checks identity itself (through jwt-router-3), so the
signatures aren't verified here.
"""

from __future__ import annotations

import base64
import json
from typing import Any


def jwt_claims(token: str | None) -> dict[str, Any]:
    """Return a JWT's payload, or {} if it isn't a JWT."""
    if not token or token.count(".") != 2:
        return {}
    payload = token.split(".")[1]
    try:
        decoded = json.loads(
            base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        )
    except ValueError:
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _nested(claims: dict[str, Any], dotted: str) -> Any:
    """Look up "user.uuid" as a flat key or as nested objects."""
    if dotted in claims:
        return claims[dotted]
    value: Any = claims
    for part in dotted.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def user_uuid(token: dict[str, Any]) -> str | None:
    """Return the Ezlo user_uuid from the access token's user envelope."""
    value = _nested(jwt_claims(token.get("access_token")), "user.uuid")
    return str(value) if value else None


def user_email(token: dict[str, Any]) -> str | None:
    """Return the email from the id_token, when the email scope was granted."""
    value = jwt_claims(token.get("id_token")).get("email")
    return str(value) if value else None
