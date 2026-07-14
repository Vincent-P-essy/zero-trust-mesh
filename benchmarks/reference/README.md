# Reviewed reference run

`reference-run.json` is a committed benchmark output over the synthetic mesh,
produced by:

```bash
ZTMESH_SOURCE_REVISION=reference ZTMESH_SOURCE_TREE_STATE=clean-checkout \
  uv run ztmesh benchmark --iterations 200 --out benchmarks/reference
```

`inputs.sha256` pins the deterministic inputs that drive the run. CI verifies
them with `sha256sum --check benchmarks/reference/inputs.sha256`, so any change
to a fixture that alters behaviour must be reviewed alongside the ground truth.

## What the run establishes

- **Correctness.** All nine continuous-verification scenarios reproduce their
  declared step effects and final session state (`matched_scenarios == 9`,
  `ground_truth_verified == true`). The scenarios are cross-checked against the
  committed `fixtures/ground-truth.json` by a test.
- **Determinism.** Every one of the 200 passes produces a byte-identical outcome
  mapping, collapsed to a single `report_hash`. `deterministic == true` asserts
  the whole suite hashed to exactly one value.
- **Latency.** Timing covers authentication (including RSA token and certificate
  operations in the token-revocation scenario), trust scoring, policy decision,
  and session-state updates. It excludes HTTP and the dashboard.

Latency is machine dependent and is not asserted in CI; only correctness,
determinism, and input integrity are. Reproduce the numbers locally rather than
trusting the committed timing on another host.
