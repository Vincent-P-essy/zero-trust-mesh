# Limitations

This is a portfolio-grade prototype over synthetic data. It is designed to make
a Zero Trust *architecture* legible and demonstrable, not to replace a
production access platform.

- **Synthetic environment.** Principals, devices, resources, policies, and
  networks are fixtures. Device posture and network reputation are declared, not
  observed from a real MDM or threat-intel feed.
- **Identity provider.** The OIDC provider is minimal: no user database, consent
  flow, refresh tokens, or discovery document beyond JWKS. RSA keys are sized for
  fast tests. Do not point real clients at it.
- **mTLS.** The CA models workload *identity* (SPIFFE X.509) and its
  verification. It does not perform TLS handshakes or encrypt transport; that is
  the runtime's job. Revocation of leaf certificates relies on their short
  lifetime, not a CRL or OCSP.
- **Trust scoring.** Weights are illustrative and fixed, not calibrated against
  incident data. The score is a relative comparison heuristic, not a probability
  of compromise, expected loss, or a compliance grade.
- **Policy coverage.** The engine models role/group/service/sensitivity
  selectors, trust floors, assurance, device, and network conditions. It does
  not model time-of-day windows, resource hierarchies, delegation, break-glass,
  or obligations beyond step-up.
- **Continuous verification cadence.** Re-evaluation happens on each request in
  this model. A real deployment must also handle long-lived connections and
  streaming, where re-checks are driven by a timer or an event bus.
- **Local API.** The HTTP surface is unauthenticated and for loopback only. It is
  a dashboard and exploration tool, not a hardened authorization server.

Read the [threat model](THREAT_MODEL.md) and [trust model](TRUST_MODEL.md)
before interpreting any decision the mesh produces.
