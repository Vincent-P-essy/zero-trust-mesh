"""A minimal, self-contained OpenID-Connect-style identity provider.

The provider issues and verifies RS256 JSON Web Tokens, publishes a JWKS
document with key rotation, supports RFC 7662-style introspection, and maintains
a ``jti`` revocation list. It is deliberately small: it demonstrates the token
mechanics a Zero Trust mesh relies on, not a certified OIDC deployment. There is
no user database, consent screen, or refresh-token rotation.

Tokens carry a ``cnf`` confirmation claim so the enforcement point can bind a
bearer token to the workload certificate that presented it (proof-of-possession
in the spirit of RFC 8705), and a ``device`` claim so device posture can be
re-checked at every request rather than only at login.
"""

from __future__ import annotations

import base64
import hashlib
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from .models import AssuranceLevel

ISSUER = "https://idp.mesh.internal"
ALGORITHM = "RS256"
DEFAULT_TTL_SECONDS = 900


def _b64url_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class SigningKey:
    kid: str
    private_key: rsa.RSAPrivateKey

    @property
    def public_numbers(self) -> rsa.RSAPublicNumbers:
        return self.private_key.public_key().public_numbers()

    def jwk(self) -> dict[str, str]:
        numbers = self.public_numbers
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": ALGORITHM,
            "kid": self.kid,
            "n": _b64url_uint(numbers.n),
            "e": _b64url_uint(numbers.e),
        }


@dataclass
class IntrospectionResult:
    active: bool
    claims: dict[str, Any] = field(default_factory=dict)
    reason: str = ""


class TokenError(Exception):
    """Raised when a token cannot be verified."""


class IdentityProvider:
    """Issues and verifies short-lived assertions for mesh principals.

    ``key_size`` is kept small by default so tests and benchmarks run quickly;
    deployments would use 2048 bits or more. The value never leaves the process
    and signs only synthetic tokens.
    """

    def __init__(self, *, key_size: int = 2048, clock: Any = time.time) -> None:
        self._clock = clock
        self._keys: dict[str, SigningKey] = {}
        self._active_kid: str = ""
        self._revoked: set[str] = set()
        self.rotate_key(key_size=key_size)

    def rotate_key(self, *, key_size: int = 2048) -> str:
        """Generate a new signing key, make it active, and return its ``kid``."""

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        kid = uuid.uuid5(uuid.NAMESPACE_OID, f"ztmesh-{len(self._keys)}-{key_size}").hex[:16]
        self._keys[kid] = SigningKey(kid=kid, private_key=private_key)
        self._active_kid = kid
        return kid

    def jwks(self) -> dict[str, list[dict[str, str]]]:
        """Return the public JWKS document with every non-retired key."""

        return {"keys": [key.jwk() for key in self._keys.values()]}

    def issue(
        self,
        *,
        subject: str,
        audience: str,
        device_id: str,
        assurance: AssuranceLevel = AssuranceLevel.MULTI_FACTOR,
        amr: tuple[str, ...] = ("pwd", "otp"),
        confirmation: str | None = None,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> str:
        """Sign and return a JWT for ``subject`` scoped to ``audience``.

        ``confirmation`` is the SHA-256 thumbprint of the presenting workload
        certificate; when set it is embedded as the ``cnf.x5t#S256`` claim.
        """

        key = self._keys[self._active_kid]
        now = int(self._clock())
        claims: dict[str, Any] = {
            "iss": ISSUER,
            "sub": subject,
            "aud": audience,
            "iat": now,
            "nbf": now,
            "exp": now + ttl_seconds,
            "jti": uuid.uuid4().hex,
            "acr": assurance.value,
            "amr": list(amr),
            "device": device_id,
        }
        if confirmation is not None:
            claims["cnf"] = {"x5t#S256": confirmation}
        return jwt.encode(
            claims, self._private_pem(key), algorithm=ALGORITHM, headers={"kid": key.kid}
        )

    def verify(self, token: str, *, audience: str) -> dict[str, Any]:
        """Verify a token's signature and claims, returning the payload.

        Raises :class:`TokenError` on any failure, including revocation. The
        caller is responsible for the confirmation (``cnf``) binding check,
        which requires the presented certificate thumbprint.
        """

        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError as exc:  # pragma: no cover - defensive
            raise TokenError(f"malformed token header: {exc}") from exc
        kid = header.get("kid")
        if kid not in self._keys:
            raise TokenError("unknown signing key")
        key = self._keys[kid]
        try:
            payload: dict[str, Any] = jwt.decode(
                token,
                self._public_pem(key),
                algorithms=[ALGORITHM],
                audience=audience,
                issuer=ISSUER,
                options={"require": ["exp", "iat", "nbf", "sub", "jti", "aud"]},
            )
        except jwt.InvalidTokenError as exc:
            raise TokenError(str(exc)) from exc
        if payload["jti"] in self._revoked:
            raise TokenError("token has been revoked")
        return payload

    def introspect(self, token: str, *, audience: str) -> IntrospectionResult:
        """Return an RFC 7662-style active/inactive result without raising."""

        try:
            claims = self.verify(token, audience=audience)
        except TokenError as exc:
            return IntrospectionResult(active=False, reason=str(exc))
        return IntrospectionResult(active=True, claims=claims)

    def revoke(self, jti: str) -> None:
        """Add a token id to the revocation list; future checks fail closed."""

        self._revoked.add(jti)

    def is_revoked(self, jti: str) -> bool:
        return jti in self._revoked

    @staticmethod
    def certificate_thumbprint(certificate_der: bytes) -> str:
        """Return the base64url SHA-256 thumbprint used in ``cnf.x5t#S256``."""

        digest = hashlib.sha256(certificate_der).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    @staticmethod
    def _private_pem(key: SigningKey) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return key.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    @staticmethod
    def _public_pem(key: SigningKey) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return key.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
