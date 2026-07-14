# Trust model

Trust is a single score in `[0, 100]` produced by a fixed, documented function.
It is a comparison heuristic for the same environment before and after a change,
not a probability of compromise.

## Components and weights

The three primary components are combined as a weighted mean:

| Component | Weight | Source |
|---|---:|---|
| Identity | 0.35 | authentication assurance level and methods |
| Device | 0.40 | attested endpoint posture |
| Network | 0.25 | origin network reputation |

### Identity

| Assurance (NIST AAL) | Base score |
|---|---:|
| `aal0` none | 10 |
| `aal1` single factor | 45 |
| `aal2` multi factor | 80 |
| `aal3` hardware | 95 |

A phishing-resistant authenticator (`webauthn`, `hwk`) adds 5, capped at 100.

### Device

A fully compliant device scores 100 before penalties. Controls contribute:
managed 24, disk encryption 20, EDR 18, secure boot 14, screen lock 12,
firewall 12. Patch age subtracts up to 24 points on a step function, and a
detected jailbreak subtracts 60. If the attestation is older than 12 hours the
posture is treated as unknown: the device scores 5 and the whole assessment is
marked **fail-closed**, which the decision point turns into a denial.

### Network

Baseline 55; a corporate range adds 30; a Tor exit subtracts 55; an anonymizing
VPN subtracts 25.

## Behavioural penalties (continuous verification)

After the blend, session-level penalties are subtracted:

- **Session decay** — after a 15-minute grace period, 4 points per 5-minute
  block, capped at 40. A session that runs untouched slowly loses trust.
- **Impossible travel** — a 45-point penalty when the origin country changes
  within an hour of the previous request.
- **New device** — a 15-point penalty for a device not previously seen in the
  session.

Every component and penalty is recorded as a `TrustFactor` with its numeric
contribution and a human-readable reason, so any score can be explained without
re-running the engine. The weights are deliberately legible rather than tuned;
they are illustrative of an architecture, not calibrated against incident data.
