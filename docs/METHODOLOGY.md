# Methodology

How the measured evidence is produced and what it does and does not cover.

## Ground truth

Each scenario in `scenarios.py` declares the expected decision effect of every
step and the expected final session state. That declaration is the ground truth.
It is also exported to `fixtures/ground-truth.json`, and a test asserts the two
are identical, so the committed fixture cannot drift from the code.

## Correctness

`ztmesh benchmark` runs the full scenario suite and compares every step and final
state to the ground truth. `matched_scenarios == scenarios` and
`ground_truth_verified == true` mean every declared outcome reproduced. Because
the scenarios exercise permit, deny, step-up, revoke, impossible travel, and
live token revocation, a regression in any decision path surfaces as a changed
outcome, not a changed number.

## Determinism

The benchmark runs the suite `iterations` times and hashes the outcome mapping
(effects and final states) each pass. `deterministic == true` means all passes
produced a single identical hash. The hash excludes timing so a slow runner does
not change the recorded evidence.

## Latency

Timing measures the evaluation path: authentication (including RSA token and
certificate operations in the token-revocation scenario), trust scoring, policy
decision, and session-state updates. It excludes HTTP, the dashboard, and any
real network or MDM collection, which do not exist here. Latency is machine
dependent; CI does not assert it. Reproduce locally:

```bash
uv run ztmesh benchmark --iterations 200
```

## Input integrity

`benchmarks/reference/inputs.sha256` pins the fixtures that drive the run. CI
checks them so a behavioural change to a fixture is reviewed with its ground
truth rather than landing silently.
