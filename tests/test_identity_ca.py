from __future__ import annotations

import datetime as dt
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from zero_trust_mesh.ca import CertificateError, WorkloadCA
from zero_trust_mesh.identity import IdentityProvider, TokenError
from zero_trust_mesh.models import AssuranceLevel
from zero_trust_mesh.pep import PolicyEnforcementPoint


class MutableClock:
    def __init__(self, value: float) -> None:
        self.value = value

    def __call__(self) -> float:
        return self.value


def test_issue_and_verify_token() -> None:
    idp = IdentityProvider()
    token = idp.issue(subject="alice", audience="mesh.internal", device_id="laptop")
    claims = idp.verify(token, audience="mesh.internal")
    assert claims["sub"] == "alice"
    assert claims["device"] == "laptop"
    assert claims["acr"] == AssuranceLevel.MULTI_FACTOR.value


def test_wrong_audience_is_rejected() -> None:
    idp = IdentityProvider()
    token = idp.issue(subject="alice", audience="mesh.internal", device_id="laptop")
    with pytest.raises(TokenError):
        idp.verify(token, audience="other")


def test_revoked_token_fails() -> None:
    idp = IdentityProvider()
    token = idp.issue(subject="alice", audience="mesh.internal", device_id="laptop")
    result = idp.introspect(token, audience="mesh.internal")
    idp.revoke(str(result.claims["jti"]))
    assert idp.is_revoked(str(result.claims["jti"]))
    with pytest.raises(TokenError):
        idp.verify(token, audience="mesh.internal")
    assert idp.introspect(token, audience="mesh.internal").active is False


def test_expired_token_fails() -> None:
    idp = IdentityProvider(clock=lambda: time.time() - 10_000)
    token = idp.issue(subject="alice", audience="mesh.internal", device_id="laptop", ttl_seconds=60)
    with pytest.raises(TokenError):
        idp.verify(token, audience="mesh.internal")


def test_unknown_signing_key() -> None:
    idp = IdentityProvider()
    other = IdentityProvider()
    token = other.issue(subject="alice", audience="mesh.internal", device_id="laptop")
    with pytest.raises(TokenError):
        idp.verify(token, audience="mesh.internal")


def test_key_rotation_keeps_old_keys_in_jwks() -> None:
    idp = IdentityProvider()
    first = idp.issue(subject="a", audience="mesh.internal", device_id="d")
    idp.rotate_key()
    second = idp.issue(subject="a", audience="mesh.internal", device_id="d")
    # Both tokens still verify because the old public key remains in the JWKS.
    assert idp.verify(first, audience="mesh.internal")["sub"] == "a"
    assert idp.verify(second, audience="mesh.internal")["sub"] == "a"
    assert len(idp.jwks()["keys"]) == 2


def test_ca_issues_and_verifies_spiffe_identity() -> None:
    ca = WorkloadCA(trust_domain="mesh.internal")
    identity = ca.issue("payments")
    assert identity.spiffe_id == "spiffe://mesh.internal/payments"
    assert ca.verify(identity.certificate) == identity.spiffe_id


def test_ca_rejects_foreign_certificate() -> None:
    ca = WorkloadCA()
    other = WorkloadCA()
    foreign = other.issue("payments")
    with pytest.raises(CertificateError):
        ca.verify(foreign.certificate)


def test_ca_rejects_expired_certificate() -> None:
    clock = MutableClock(0.0)
    base = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)

    def as_datetime() -> dt.datetime:
        return base + dt.timedelta(seconds=clock.value)

    ca = WorkloadCA(clock=as_datetime)
    identity = ca.issue("payments", ttl_seconds=60)
    clock.value = 10_000  # advance well past the leaf validity window
    with pytest.raises(CertificateError):
        ca.verify(identity.certificate)


def _forge(ca: WorkloadCA, sans: list[x509.GeneralName]) -> x509.Certificate:
    key = ca._key
    from cryptography.hazmat.primitives.asymmetric import rsa

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(tz=dt.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "forged")]))
        .issuer_name(ca.root_certificate.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(hours=1))
    )
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=True)
    return builder.sign(key, hashes.SHA256())


def test_ca_requires_exactly_one_spiffe_uri() -> None:
    ca = WorkloadCA(trust_domain="mesh.internal")
    without_san = _forge(ca, [])
    with pytest.raises(CertificateError):
        ca.verify(without_san)


def test_ca_rejects_foreign_trust_domain() -> None:
    ca = WorkloadCA(trust_domain="mesh.internal")
    wrong = _forge(ca, [x509.UniformResourceIdentifier("spiffe://evil.example/payments")])
    with pytest.raises(CertificateError):
        ca.verify(wrong)


def test_pep_authenticates_bound_token() -> None:
    idp = IdentityProvider()
    ca = WorkloadCA(trust_domain="mesh.internal")
    pep = PolicyEnforcementPoint(idp, ca)
    identity = ca.issue("workstation-agent")
    thumbprint = idp.certificate_thumbprint(identity.certificate_der)
    token = idp.issue(
        subject="alice",
        audience="mesh.internal",
        device_id="laptop-alice",
        confirmation=thumbprint,
    )
    result = pep.authenticate(
        token=token, audience="mesh.internal", certificate_der=identity.certificate_der
    )
    assert result.authenticated is True
    assert result.subject == "alice"
    assert result.spiffe_id == "spiffe://mesh.internal/workstation-agent"


def test_pep_rejects_binding_mismatch() -> None:
    idp = IdentityProvider()
    ca = WorkloadCA(trust_domain="mesh.internal")
    pep = PolicyEnforcementPoint(idp, ca)
    bound = ca.issue("workstation-agent")
    other = ca.issue("another-agent")
    thumbprint = idp.certificate_thumbprint(bound.certificate_der)
    token = idp.issue(
        subject="alice", audience="mesh.internal", device_id="d", confirmation=thumbprint
    )
    result = pep.authenticate(
        token=token, audience="mesh.internal", certificate_der=other.certificate_der
    )
    assert result.authenticated is False
    assert any("binding" in failure for failure in result.failures)


def test_pep_flags_missing_certificate_for_bound_token() -> None:
    idp = IdentityProvider()
    ca = WorkloadCA(trust_domain="mesh.internal")
    pep = PolicyEnforcementPoint(idp, ca)
    identity = ca.issue("workstation-agent")
    thumbprint = idp.certificate_thumbprint(identity.certificate_der)
    token = idp.issue(
        subject="alice", audience="mesh.internal", device_id="d", confirmation=thumbprint
    )
    result = pep.authenticate(token=token, audience="mesh.internal", certificate_der=None)
    assert result.authenticated is False


def test_pep_accepts_unbound_token_without_certificate() -> None:
    idp = IdentityProvider()
    ca = WorkloadCA(trust_domain="mesh.internal")
    pep = PolicyEnforcementPoint(idp, ca)
    token = idp.issue(subject="alice", audience="mesh.internal", device_id="d")
    result = pep.authenticate(token=token, audience="mesh.internal", certificate_der=None)
    assert result.authenticated is True


def test_pep_reports_invalid_token() -> None:
    idp = IdentityProvider()
    ca = WorkloadCA(trust_domain="mesh.internal")
    pep = PolicyEnforcementPoint(idp, ca)
    result = pep.authenticate(
        token="not-a-token",  # noqa: S106
        audience="mesh.internal",
        certificate_der=None,
    )
    assert result.authenticated is False
