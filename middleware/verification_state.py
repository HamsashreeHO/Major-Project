"""In-memory verification records, attempt limits and nonce binding.

State is per-process and lost on restart (prototype limitation). Keys contain
the Aadhaar number only in memory; nothing here is logged or persisted.
"""
import time

VERIFICATION_TTL_SECONDS = 10 * 60
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 15 * 60


def session_binding(session_id, email, aadhaar_id):
    """String the nonce is bound to: session + signed-in applicant + Aadhaar ID."""
    return "|".join((str(session_id), str(email), str(aadhaar_id)))


class VerificationState:
    def __init__(self, clock=time.monotonic, ttl_seconds=VERIFICATION_TTL_SECONDS,
                 max_failures=MAX_FAILED_ATTEMPTS, lockout_seconds=LOCKOUT_SECONDS):
        self.clock = clock
        self.ttl_seconds = ttl_seconds
        self.max_failures = max_failures
        self.lockout_seconds = lockout_seconds
        self._verified = {}
        self._failures = {}

    # ── verification records (single use, short TTL) ──
    def mark_verified(self, binding):
        self._verified[binding] = self.clock() + self.ttl_seconds

    def consume_verified(self, binding):
        expires_at = self._verified.pop(binding, None)
        return expires_at is not None and self.clock() <= expires_at

    # ── attempt limits ──
    def is_locked(self, *keys):
        now = self.clock()
        for key in keys:
            state = self._failures.get(key)
            if state and state.get("locked_until", 0) > now:
                return True
        return False

    def record_failure(self, *keys):
        now = self.clock()
        for key in keys:
            state = self._failures.get(key)
            if not state or now - state["since"] > self.lockout_seconds:
                state = {"count": 0, "since": now}
                self._failures[key] = state
            state["count"] += 1
            if state["count"] >= self.max_failures:
                state["locked_until"] = now + self.lockout_seconds

    def reset(self, *keys):
        for key in keys:
            self._failures.pop(key, None)
