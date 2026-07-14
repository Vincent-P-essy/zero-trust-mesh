# Threat model

The mesh demonstrates how a Zero Trust architecture contains specific threats.
It operates on synthetic data and models identity and authorization, not
transport security or a production control plane.

## Assets

- The protected resources (payments ledger, customer PII, deployment pipeline,
  audit store) and their data classifications.
- The integrity of the decision path: no request should be permitted without a
  fresh, evidence-backed decision.

## Threats addressed

| Threat | Control | Scenario |
|---|---|---|
| Stolen bearer token replayed from another host | `cnf` certificate binding (proof of possession) | `token-revoked-mid-session`, PEP binding tests |
| Token still valid after logout / compromise | `jti` revocation checked on every request | `token-revoked-mid-session` |
| Session stays trusted after the device degrades | posture re-scored every request; stale attestation fails closed and revokes | `posture-drop-revoke` |
| Credentials used from an unexpected location | impossible-travel penalty collapses trust | `impossible-travel-deny` |
| Access from an unmanaged or anonymized origin | `require_managed_device`, `forbid_anonymized_network` | `unmanaged-audit-deny`, `anonymized-network-deny` |
| External principal reaching restricted data | deny-override rule | `external-restricted-deny` |
| Over-broad standing access | least privilege by resource sensitivity and trust floor | `baseline-permit`, `public-low-trust-permit` |

## Threats explicitly out of scope

- **Transport security.** The CA proves *which workload* is calling; it does not
  perform a TLS handshake or encrypt traffic. A real deployment terminates mTLS
  in the sidecar or service mesh runtime.
- **A hardened identity provider.** The bundled OIDC provider has no user store,
  consent, refresh-token rotation, or hardware-backed keys, and signs only
  synthetic tokens with test-sized RSA keys.
- **Policy administration security.** Policy files are trusted inputs; the model
  does not cover who may edit them or how they are signed and distributed.
- **Denial of service, side channels, and supply-chain integrity** of the mesh
  itself.

## Fail-closed posture

Unresolved subject/device/resource, stale attestation, invalid or revoked token,
and broken certificate binding all deny. A previously revoked session stays
revoked until re-authentication even if later signals look healthy.
