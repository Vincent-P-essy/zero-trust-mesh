# Contributing

Every change to a decision path needs:

1. a positive test that the request is permitted under the intended conditions;
2. a negative test that it is denied or stepped up when a condition fails;
3. a continuous-verification test when the change affects mid-session behaviour
   (trust decay, posture change, revocation, or session state);
4. a ground-truth review if any scenario outcome or final session state changes.

Trust scoring and policy evaluation must stay deterministic: identical inputs
must yield identical decisions, and the benchmark must remain reproducible with a
single stable outcome hash. Do not introduce a language model, randomness, or
wall-clock dependence into the decision path.

Authentication must fail closed. An unresolved subject, a stale attestation, an
invalid or revoked token, or a broken certificate binding must deny rather than
degrade to an allow.

Run before submitting:

```bash
uv sync --frozen --all-extras
make lint
make test
make benchmark
sha256sum --check benchmarks/reference/inputs.sha256
docker compose config --quiet
docker build -t zero-trust-mesh:test .
```

Do not commit real credentials, certificates, or generated co-author trailers.
Keep security claims tied to reproducible evidence and document the false
positive and false negative boundaries of any new signal.
