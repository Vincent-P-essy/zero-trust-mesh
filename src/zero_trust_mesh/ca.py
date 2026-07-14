"""An in-memory workload certificate authority for mesh mTLS identity.

The CA issues short-lived leaf certificates whose only subject identifier is a
SPIFFE URI SAN (``spiffe://<trust-domain>/<path>``), following the SPIFFE X.509
identity document convention. Verification checks the signature chains to this
CA, the certificate is inside its validity window, and a SPIFFE URI is present.

This models the identity half of mutual TLS: it proves *which workload* is on
the other end of a connection. It does not perform a TLS handshake or transport
encryption; those are the responsibility of the runtime the mesh would deploy
into. Keys and certificates are synthetic and never leave the process.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

LEAF_TTL_SECONDS = 3_600


class CertificateError(Exception):
    """Raised when a presented workload certificate fails verification."""


@dataclass(frozen=True)
class IssuedIdentity:
    """A leaf certificate plus its private key and SPIFFE identity."""

    spiffe_id: str
    service: str
    certificate: x509.Certificate
    private_key: rsa.RSAPrivateKey

    @property
    def certificate_der(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.DER)

    @property
    def certificate_pem(self) -> bytes:
        return self.certificate.public_bytes(serialization.Encoding.PEM)


class WorkloadCA:
    """Issues and verifies SPIFFE-identified workload certificates."""

    def __init__(self, *, trust_domain: str = "mesh.internal", clock: Any = None) -> None:
        self.trust_domain = trust_domain
        self._clock = clock or (lambda: dt.datetime.now(tz=dt.UTC))
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._certificate = self._build_root()

    @property
    def root_certificate(self) -> x509.Certificate:
        return self._certificate

    def spiffe_id(self, path: str) -> str:
        clean = path.strip("/")
        return f"spiffe://{self.trust_domain}/{clean}"

    def issue(self, service: str, *, ttl_seconds: int = LEAF_TTL_SECONDS) -> IssuedIdentity:
        """Issue a leaf certificate for ``service`` with a SPIFFE URI SAN."""

        now = self._now()
        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        spiffe = self.spiffe_id(service)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, service)])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._certificate.subject)
            .public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(seconds=30))
            .not_valid_after(now + dt.timedelta(seconds=ttl_seconds))
            .add_extension(
                x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe)]), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]
                ),
                critical=False,
            )
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(self._key, hashes.SHA256())
        )
        return IssuedIdentity(
            spiffe_id=spiffe, service=service, certificate=certificate, private_key=leaf_key
        )

    def verify(self, certificate: x509.Certificate) -> str:
        """Verify a leaf certificate and return its SPIFFE id.

        Checks: the signature was produced by this CA, the current time is
        within the validity window, and exactly one SPIFFE URI SAN is present.
        """

        public_key = self._certificate.public_key()
        if not isinstance(public_key, rsa.RSAPublicKey):  # pragma: no cover - CA key is RSA
            raise CertificateError("authority key is not RSA")
        try:
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                _pkcs1v15(),
                certificate.signature_hash_algorithm,  # type: ignore[arg-type]
            )
        except Exception as exc:
            raise CertificateError("certificate not signed by this authority") from exc

        now = self._now()
        if now < certificate.not_valid_before_utc or now > certificate.not_valid_after_utc:
            raise CertificateError("certificate is outside its validity window")

        uris = self._spiffe_uris(certificate)
        if len(uris) != 1:
            raise CertificateError("certificate must carry exactly one SPIFFE URI SAN")
        spiffe = uris[0]
        if not spiffe.startswith(f"spiffe://{self.trust_domain}/"):
            raise CertificateError("SPIFFE identity is outside the trust domain")
        return spiffe

    @staticmethod
    def _spiffe_uris(certificate: x509.Certificate) -> list[str]:
        try:
            san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        except x509.ExtensionNotFound:
            return []
        return [uri for uri in san.value.get_values_for_type(x509.UniformResourceIdentifier)]

    def _now(self) -> dt.datetime:
        value = self._clock()
        if value.tzinfo is None:
            return value.replace(tzinfo=dt.UTC)
        return value

    def _build_root(self) -> x509.Certificate:
        now = self._now()
        name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, f"ztmesh-ca.{self.trust_domain}")]
        )
        return (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self._key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1))
            .not_valid_after(now + dt.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(self._key, hashes.SHA256())
        )


def _pkcs1v15() -> Any:
    from cryptography.hazmat.primitives.asymmetric import padding

    return padding.PKCS1v15()
