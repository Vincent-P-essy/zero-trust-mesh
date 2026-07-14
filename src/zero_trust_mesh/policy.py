"""Policy matching primitives.

A :class:`~zero_trust_mesh.models.Selector` matches a request when every
populated dimension matches. An empty dimension is a wildcard for that
dimension, and ``actions`` supports a trailing ``*`` glob. The decision logic
that consumes these matches lives in :mod:`zero_trust_mesh.pdp`.
"""

from __future__ import annotations

from fnmatch import fnmatchcase

from .models import Principal, Resource, Selector


def _matches_any(candidates: tuple[str, ...], value: str) -> bool:
    return any(fnmatchcase(value, pattern) for pattern in candidates)


def selector_matches(
    selector: Selector,
    *,
    principal: Principal,
    resource: Resource,
    action: str,
) -> bool:
    """Return ``True`` when ``selector`` matches the request tuple."""

    if selector.principals and not _matches_any(selector.principals, principal.id):
        return False
    if selector.roles and not any(role in selector.roles for role in principal.roles):
        return False
    if selector.groups and not any(group in selector.groups for group in principal.groups):
        return False
    if selector.services and resource.service not in selector.services:
        return False
    if selector.resources and not _matches_any(selector.resources, resource.id):
        return False
    if selector.sensitivities and resource.sensitivity not in selector.sensitivities:
        return False
    return not (selector.actions and not _matches_any(selector.actions, action))
