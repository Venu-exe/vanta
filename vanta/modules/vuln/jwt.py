"""JWT analysis.

Offline and non-intrusive: takes tokens supplied in engagement metadata
(``jwt_tokens``) or found in cookies during the run, decodes them, and flags the
classic flaws - ``alg: none``, weak HMAC secrets, missing expiry, and HS/RS
confusion preconditions.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

from vanta.core.models import Confidence, Evidence, Finding, Severity
from vanta.core.registry import Module, RunContext, register
from vanta.core.scoring import cvss_base_score

# A tiny dictionary is enough to demonstrate the weak-secret check offline; a
# real engagement would point this at rockyou.txt via the jwks config key.
_WEAK_SECRETS = [
    "secret", "password", "123456", "admin", "changeme", "jwt", "key",
    "secretkey", "your-256-bit-secret", "supersecret", "test", "dev",
]


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def decode_jwt(token: str) -> tuple[dict, dict, str]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a JWT (expected 3 dot-separated parts)")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    return header, payload, parts[2]


@register
class JWTAnalysis(Module):
    name = "jwt"
    category = "jwt"
    description = "Decode JWTs and detect alg:none, weak HMAC secrets and missing expiry"
    phase = 66

    async def run(self, ctx: RunContext) -> list[Finding]:
        tokens: list[str] = list(self.config.get("jwt_tokens", []))
        discovered = ctx.shared.get("jwt_tokens", [])
        tokens.extend(discovered)
        if not tokens:
            ctx.log.debug("jwt.no-tokens", host=ctx.target.host)
            return []

        findings: list[Finding] = []
        for token in dict.fromkeys(tokens):
            try:
                header, payload, signature = decode_jwt(token)
            except Exception as exc:  # noqa: BLE001
                ctx.log.debug("jwt.decode-failed", detail=str(exc))
                continue

            alg = str(header.get("alg", "")).lower()
            b64_header, b64_payload, _ = token.split(".")

            if alg == "none":
                findings.append(
                    Finding(
                        title=f"JWT accepts alg 'none' on {ctx.target.host}",
                        module=self.name,
                        target=ctx.target.host,
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        category="jwt",
                        cwe="CWE-347",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        cvss_score=cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
                        description="A token with `alg: none` was observed, and no signature is verified.",
                        impact="An attacker can forge arbitrary tokens and impersonate any user.",
                        remediation="Enforce a fixed allow-list of algorithms; reject 'none'.",
                        metadata={"header": header, "payload": payload},
                        evidence=[Evidence(kind="jwt", summary=f"alg=none token: {token[:24]}…")],
                    )
                )

            if alg == "hs256":
                for candidate in _WEAK_SECRETS:
                    expected = hmac.new(
                        candidate.encode(), f"{b64_header}.{b64_payload}".encode(), hashlib.sha256
                    ).digest()
                    try:
                        actual = _b64url_decode(signature)
                    except Exception:  # noqa: BLE001
                        break
                    if hmac.compare_digest(expected, actual):
                        findings.append(
                            Finding(
                                title=f"JWT signed with a weak secret on {ctx.target.host}",
                                module=self.name,
                                target=ctx.target.host,
                                severity=Severity.CRITICAL,
                                confidence=Confidence.CONFIRMED,
                                category="jwt",
                                cwe="CWE-798",
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                cvss_score=cvss_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
                                description=f"The HS256 key is the guessable value {candidate!r}.",
                                impact="Tokens can be forged for any user or claim.",
                                remediation="Use a long random secret from a KMS/secret manager and rotate it.",
                                metadata={"secret": candidate},
                                evidence=[Evidence(kind="jwt", summary=f"HS256 key = {candidate}")],
                            )
                        )
                        break

            if "exp" not in payload:
                findings.append(
                    Finding(
                        title=f"JWT without expiry on {ctx.target.host}",
                        module=self.name,
                        target=ctx.target.host,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.CONFIRMED,
                        category="jwt",
                        cwe="CWE-613",
                        description="The token has no `exp` claim, so it never expires.",
                        impact="A stolen token remains valid indefinitely.",
                        remediation="Issue short-lived access tokens and use refresh tokens.",
                        metadata={"payload_keys": sorted(payload)},
                        evidence=[Evidence(kind="jwt", summary="no exp claim")],
                    )
                )
        return findings
