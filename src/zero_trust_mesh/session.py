"""Session state and the continuous-verification timeline.

A Zero Trust mesh does not trust a session because it authenticated once. This
module records every authorization event against a session and lets trust drive
state transitions: a session that drops below its floor becomes ``revoked`` and
stays revoked, so a later benign request from the same session is still refused
until re-authentication. That is the mechanism that turns a point-in-time login
into continuous verification.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import (
    Decision,
    DecisionEffect,
    SessionState,
    SessionSummary,
    VerificationEvent,
)


@dataclass
class Session:
    """Mutable runtime state for one authenticated session."""

    session_id: str
    principal_id: str
    device_id: str
    started_epoch: float
    state: SessionState = SessionState.ACTIVE
    last_request_epoch: float | None = None
    last_country: str | None = None
    known_devices: set[str] = field(default_factory=set)
    events: list[VerificationEvent] = field(default_factory=list)

    def age_seconds(self, at_epoch: float) -> float:
        return max(0.0, at_epoch - self.started_epoch)

    def seconds_since_last(self, at_epoch: float) -> float:
        if self.last_request_epoch is None:
            return 0.0
        return max(0.0, at_epoch - self.last_request_epoch)

    def summary(self) -> SessionSummary:
        return SessionSummary(
            session_id=self.session_id,
            principal_id=self.principal_id,
            device_id=self.device_id,
            state=self.state,
            events=tuple(self.events),
        )


class SessionStore:
    """Holds sessions and applies continuous-verification state transitions."""

    # Trust floor below which any active session is revoked outright.
    REVOKE_BELOW_TRUST = 30.0

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}

    def start(
        self,
        session_id: str,
        *,
        principal_id: str,
        device_id: str,
        at_epoch: float,
    ) -> Session:
        session = Session(
            session_id=session_id,
            principal_id=principal_id,
            device_id=device_id,
            started_epoch=at_epoch,
            known_devices={device_id},
        )
        self._sessions[session_id] = session
        return session

    def get(self, session_id: str) -> Session | None:
        return self._sessions.get(session_id)

    def ensure(
        self, session_id: str, *, principal_id: str, device_id: str, at_epoch: float
    ) -> Session:
        session = self._sessions.get(session_id)
        if session is None:
            return self.start(
                session_id, principal_id=principal_id, device_id=device_id, at_epoch=at_epoch
            )
        return session

    def record(
        self,
        session: Session,
        *,
        decision: Decision,
        at_epoch: float,
        resource_id: str,
        action: str,
    ) -> VerificationEvent:
        """Append an event, apply the resulting state, and return the event."""

        state = self._next_state(session, decision)
        session.state = state
        reason = decision.reasons[0] if decision.reasons else decision.effect.value
        event = VerificationEvent(
            sequence=len(session.events),
            at_epoch=at_epoch,
            resource_id=resource_id,
            action=action,
            effect=decision.effect,
            trust_score=decision.trust.score,
            state=state,
            reason=reason,
        )
        session.events.append(event)
        session.last_request_epoch = at_epoch
        return event

    def _next_state(self, session: Session, decision: Decision) -> SessionState:
        # A revoked session never returns to active on its own.
        if session.state is SessionState.REVOKED:
            return SessionState.REVOKED
        if decision.trust.fail_closed or decision.trust.score < self.REVOKE_BELOW_TRUST:
            return SessionState.REVOKED
        if decision.effect is DecisionEffect.STEP_UP:
            return SessionState.STEP_UP_REQUIRED
        if decision.effect is DecisionEffect.DENY:
            # A single policy deny does not tear down the session unless trust
            # collapsed (handled above); the principal may simply lack a grant.
            return session.state
        return SessionState.ACTIVE
