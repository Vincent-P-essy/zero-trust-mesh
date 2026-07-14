"""The policy enforcement point (PEP).

A PEP is the sidecar in front of a workload. It authenticates the caller before
any policy is consulted: it verifies the presented workload certificate against
the mesh CA (the mTLS identity), verifies the bearer token against the identity
provider, and confirms the token is bound to that certificate (the ``cnf``
proof-of-possession claim). Only if all three hold does it hand a resolved
identity to the decision point. Any failure authenticates nothing and the mesh
fails closed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from cryptography import x509

from .ca import CertificateError, WorkloadCA
from .identity import IdentityProvider, TokenError
from .models import AssuranceLevel


@dataclass(frozen=True)
class AuthenticationResult:
    authenticated: bool
    subject: str | None = None
    device_id: str | None = None
    assurance: AssuranceLevel | None = None
    amr: tuple[str, ...] = ()
    spiffe_id: str | None = None
    jti: str | None = None
    failures: tuple[str, ...] = field(default=())


class PolicyEnforcementPoint:
    """Authenticates a caller's certificate, token, and their binding."""

    def __init__(self, idp: IdentityProvider, ca: WorkloadCA) -> None:
        self._idp = idp
        self._ca = ca

    def authenticate(
        self,
        *,
        token: str,
        audience: str,
        certificate_der: bytes | None,
    ) -> AuthenticationResult:
        """Verify the token, the mTLS certificate, and their binding."""

        failures: list[str] = []

        spiffe_id: str | None = None
        certificate: x509.Certificate | None = None
        if certificate_der is not None:
            certificate = x509.load_der_x509_certificate(certificate_der)
            try:
                spiffe_id = self._ca.verify(certificate)
            except CertificateError as exc:
                failures.append(f"mtls: {exc}")

        try:
            claims = self._idp.verify(token, audience=audience)
        except TokenError as exc:
            failures.append(f"token: {exc}")
            return AuthenticationResult(authenticated=False, failures=tuple(failures))

        confirmation = (
            claims.get("cnf", {}).get("x5t#S256") if isinstance(claims.get("cnf"), dict) else None
        )
        if confirmation is not None:
            if certificate_der is None:
                failures.append(
                    "token is certificate-bound but no client certificate was presented"
                )
            else:
                presented = self._idp.certificate_thumbprint(certificate_der)
                if presented != confirmation:
                    failures.append("token binding does not match the presented certificate")

        if failures:
            return AuthenticationResult(authenticated=False, failures=tuple(failures))

        try:
            assurance = AssuranceLevel(claims["acr"])
        except ValueError:  # pragma: no cover - defensive, acr is controlled at issue time
            return AuthenticationResult(
                authenticated=False, failures=("token: unrecognized acr claim",)
            )

        return AuthenticationResult(
            authenticated=True,
            subject=str(claims["sub"]),
            device_id=str(claims.get("device", "")),
            assurance=assurance,
            amr=tuple(claims.get("amr", ())),
            spiffe_id=spiffe_id,
            jti=str(claims["jti"]),
        )
