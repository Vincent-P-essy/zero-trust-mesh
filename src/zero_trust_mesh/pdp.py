"""The policy decision point (PDP).

The PDP is the authoritative authorizer. Given a resolved request context and a
trust assessment, it selects the governing rule and returns a
:class:`~zero_trust_mesh.models.Decision`. Evaluation is deny-override: any
matching ``deny`` rule wins immediately. Among matching ``allow`` rules the
most specific one governs, and its trust, assurance, device, and network
conditions must all hold or the request is denied (or stepped up).

The default effect is deny, so a request that matches no rule is refused. Every
decision records the rule that governed it and human-readable reasons, and never
consults a language model.
"""

from __future__ import annotations

from .models import (
    ASSURANCE_RANK,
    Decision,
    DecisionEffect,
    Effect,
    NetworkContext,
    Obligation,
    PolicyRule,
    PolicySet,
    Principal,
    Resource,
    TrustAssessment,
)
from .policy import selector_matches


def _specificity(rule: PolicyRule) -> int:
    """Higher is more specific; used to order competing allow rules."""

    match = rule.match
    return (
        8 * len(match.principals)
        + 4 * len(match.resources)
        + 3 * len(match.roles)
        + 3 * len(match.groups)
        + 2 * len(match.services)
        + 2 * len(match.sensitivities)
        + sum(1 for action in match.actions if action != "*")
    )


class PolicyDecisionPoint:
    """Evaluates access requests against a :class:`PolicySet`."""

    def __init__(self, policy_set: PolicySet) -> None:
        self._policy_set = policy_set

    def authorize(
        self,
        *,
        principal: Principal,
        resource: Resource,
        action: str,
        network: NetworkContext,
        trust: TrustAssessment,
        managed_device: bool,
    ) -> Decision:
        """Return the decision governing this request."""

        matching = [
            rule
            for rule in self._policy_set.rules
            if selector_matches(rule.match, principal=principal, resource=resource, action=action)
        ]

        # Deny-override: a single matching deny rule refuses the request.
        for rule in matching:
            if rule.effect is Effect.DENY:
                return self._build(
                    principal,
                    resource,
                    action,
                    trust,
                    DecisionEffect.DENY,
                    rule.id,
                    (f"explicit deny rule '{rule.id}' matched",),
                )

        allow_rules = sorted(matching, key=_specificity, reverse=True)
        if not allow_rules:
            if self._policy_set.default_effect is Effect.ALLOW:
                return self._build(
                    principal,
                    resource,
                    action,
                    trust,
                    DecisionEffect.PERMIT,
                    None,
                    ("default allow; no rule matched",),
                )
            return self._build(
                principal,
                resource,
                action,
                trust,
                DecisionEffect.DENY,
                None,
                ("no rule permits this request; default deny",),
            )

        return self._evaluate(
            allow_rules[0], principal, resource, action, network, trust, managed_device
        )

    def _evaluate(
        self,
        rule: PolicyRule,
        principal: Principal,
        resource: Resource,
        action: str,
        network: NetworkContext,
        trust: TrustAssessment,
        managed_device: bool,
    ) -> Decision:
        hard_failures: list[str] = []
        if trust.fail_closed:
            hard_failures.append("device attestation is stale; failing closed")
        if rule.require_managed_device and not managed_device:
            hard_failures.append("rule requires a managed device")
        if rule.require_corporate_network and not network.corporate:
            hard_failures.append("rule requires a corporate network")
        if rule.forbid_anonymized_network and (network.tor_exit or network.anonymizing_vpn):
            hard_failures.append("rule forbids anonymizing networks")
        if ASSURANCE_RANK[trust.assurance] < ASSURANCE_RANK[rule.min_assurance]:
            hard_failures.append(
                f"assurance {trust.assurance.value} below required {rule.min_assurance.value}"
            )
        if hard_failures:
            return self._build(
                principal,
                resource,
                action,
                trust,
                DecisionEffect.DENY,
                rule.id,
                tuple(hard_failures),
            )

        if trust.score < rule.min_trust:
            if rule.step_up_below_trust is not None:
                return self._build(
                    principal,
                    resource,
                    action,
                    trust,
                    DecisionEffect.STEP_UP,
                    rule.id,
                    (
                        f"trust {trust.score:.1f} below floor {rule.min_trust:.1f}; "
                        "re-authentication required",
                    ),
                    (
                        Obligation(
                            kind="step_up_auth", detail=f"raise trust to >= {rule.min_trust:.1f}"
                        ),
                    ),
                )
            return self._build(
                principal,
                resource,
                action,
                trust,
                DecisionEffect.DENY,
                rule.id,
                (f"trust {trust.score:.1f} below required {rule.min_trust:.1f}",),
            )

        if rule.step_up_below_trust is not None and trust.score < rule.step_up_below_trust:
            return self._build(
                principal,
                resource,
                action,
                trust,
                DecisionEffect.STEP_UP,
                rule.id,
                (
                    f"trust {trust.score:.1f} under step-up threshold "
                    f"{rule.step_up_below_trust:.1f}",
                ),
                (Obligation(kind="step_up_auth", detail="stronger authentication requested"),),
            )

        return self._build(
            principal,
            resource,
            action,
            trust,
            DecisionEffect.PERMIT,
            rule.id,
            (f"rule '{rule.id}' permits with trust {trust.score:.1f}",),
        )

    @staticmethod
    def _build(
        principal: Principal,
        resource: Resource,
        action: str,
        trust: TrustAssessment,
        effect: DecisionEffect,
        matched: str | None,
        reasons: tuple[str, ...],
        obligations: tuple[Obligation, ...] = (),
    ) -> Decision:
        return Decision(
            effect=effect,
            principal_id=principal.id,
            resource_id=resource.id,
            action=action,
            trust=trust,
            matched_rule=matched,
            reasons=reasons,
            obligations=obligations,
        )
