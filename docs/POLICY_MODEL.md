# Policy model

Policies are declarative rules evaluated by the policy decision point. The
default effect is **deny**, so any request that matches no allow rule is refused.

## Selector matching

A rule's `match` selector matches a request when every populated dimension
matches. An empty dimension is a wildcard. Dimensions:

- `principals`, `resources`, `actions` — matched by exact value or a trailing
  `*` glob (`fnmatch`);
- `roles`, `groups` — match when the principal has any listed role/group;
- `services` — matches the resource's owning service;
- `sensitivities` — matches the resource's data classification.

## Evaluation order

1. **Deny override.** If any matching rule has `effect: deny`, the request is
   denied immediately. This mirrors the deny-override principle used by
   mainstream authorization engines.
2. **Most specific allow.** Among matching allow rules, the most specific one
   governs. Specificity weights explicit principals and resources above roles,
   groups, services, and sensitivities, above named actions.
3. **Conditions.** The governing rule's conditions must all hold:
   - hard conditions (fail closed on violation): `require_managed_device`,
     `require_corporate_network`, `forbid_anonymized_network`, `min_assurance`,
     and a fail-closed trust assessment;
   - trust floor: if `trust < min_trust`, the request is denied, or stepped up
     when `step_up_below_trust` is set;
   - step-up band: if `min_trust <= trust < step_up_below_trust`, the request is
     stepped up rather than permitted.

A **step-up** decision is not a denial: it carries an obligation instructing the
enforcement point to demand stronger authentication and retry. A session that is
stepped up enters `step_up_required`, distinct from `revoked`.

## Example

```yaml
- id: allow-finance-pii
  effect: allow
  match: { groups: [finance], services: [crm] }
  min_trust: 80
  min_assurance: aal2
  require_managed_device: true
  forbid_anonymized_network: true
  step_up_below_trust: 90
```

A finance analyst on a managed laptop with trust 81 is permitted only after a
step-up (81 is in the `[80, 90)` band); at trust 91 the same request is
permitted outright; below 80, or from an unmanaged device, it is denied.
