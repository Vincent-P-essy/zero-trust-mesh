# Security policy

Report vulnerabilities through GitHub private vulnerability reporting. Include
the affected commit, the request context, the expected decision, the observed
decision, and a minimal reproduction. Do not attach real tokens, certificates,
private keys, device inventories, or identity exports to an issue.

This project evaluates synthetic access requests. It signs only self-issued
tokens and certificates that never leave the process, and its policy decision
point fails closed: an unresolved principal, device, or resource, a stale device
attestation, an invalid or revoked token, or a broken certificate binding all
result in denial rather than a silent allow.

The local API is intentionally unauthenticated and must be bound to loopback. It
is a demonstration and dashboard surface, not a hardened authorization server.
The bundled identity provider uses short RSA keys sized for fast tests and is not
a certified OIDC deployment; do not point real clients at it.

The committed principals, devices, policies, and networks are fictional. Never
replace them with production identities, real policy exports, or live device
inventories in a public fork.
