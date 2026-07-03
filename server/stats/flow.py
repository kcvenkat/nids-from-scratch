from collections import deque
from dataclasses import dataclass, field
import time


@dataclass
class Flow:
    key: tuple
    first_seen: float
    last_seen: float
    packet_count: int = 0
    event_types: list[str] = field(default_factory=list)
    state: str = "new"
    closed: bool = False


@dataclass
class SuppressionState:
    key: tuple
    first_seen: float
    last_seen: float
    packet_count: int = 1
    intervals: deque[float] = field(default_factory=lambda: deque(maxlen=5))
    suppressing: bool = False
    suppress_until: float | None = None
    suppressed_count: int = 0


class SuppressionTracker:
    def __init__(self):
        self.states: dict[tuple, SuppressionState] = {}

    def _make_key(self, rule, event):
        return (
            rule.sid,
            event.src_ip,
            event.src_port or 0,
            event.dst_ip,
            event.dst_port or 0,
            event.protocol.lower(),
        )

    def _get_option(self, rule, name, default):
        options = rule.options or {}
        value = options.get(name)

        if value is None:
            return default

        if isinstance(default, bool):
            if isinstance(value, bool):
                return value

            if isinstance(value, str):
                normalized = value.strip().lower()
                if normalized in {"true", "1", "yes", "on"}:
                    return True
                if normalized in {"false", "0", "no", "off", ""}:
                    return False

            return bool(value)

        if isinstance(default, int):
            try:
                return int(value)
            except (TypeError, ValueError):
                return default

        if isinstance(default, float):
            try:
                return float(value)
            except (TypeError, ValueError):
                return default

        return value

    def _prune_expired(self, now: float):
        expired_keys = [
            key for key, state in self.states.items()
            if now - state.last_seen > self._get_state_ttl(key)
        ]
        for key in expired_keys:
            del self.states[key]

    def _get_state_ttl(self, key):
        return 20.0

    def _get_suppression_window(self, rule):
        return self._get_option(rule, "suppress_window", 8.0)

    def _get_min_packets(self, rule):
        return self._get_option(rule, "min_packets", 3)

    def _get_max_interval(self, rule):
        return self._get_option(rule, "max_interval", 1.0)

    def _is_enabled(self, rule):
        return True

    def should_emit_alert(self, rule, event, now: float | None = None):
        if not self._is_enabled(rule):
            return True

        now = now if now is not None else time.time()
        self._prune_expired(now)

        key = self._make_key(rule, event)
        state = self.states.get(key)

        if state is None:
            state = SuppressionState(key=key, first_seen=now, last_seen=now)
            self.states[key] = state
        else:
            gap = max(0.0, now - state.last_seen)
            state.last_seen = now
            if gap > 0:
                state.intervals.append(gap)
            state.packet_count += 1

        if state.suppressing and state.suppress_until is not None and now < state.suppress_until:
            state.suppressed_count += 1
            return False

        if now >= state.suppress_until if state.suppress_until is not None else False:
            state.suppressing = False
            state.suppress_until = None

        min_packets = self._get_min_packets(rule)
        if state.packet_count < min_packets:
            return False

        intervals = list(state.intervals)
        if len(intervals) >= 2:
            avg_interval = sum(intervals) / len(intervals)
            if avg_interval <= self._get_max_interval(rule):
                state.suppressing = True
                state.suppress_until = now + self._get_suppression_window(rule)
                return True

        return True


suppression_tracker = SuppressionTracker()


def should_emit_alert(rule, event, now: float | None = None):
    return suppression_tracker.should_emit_alert(rule, event, now=now)
