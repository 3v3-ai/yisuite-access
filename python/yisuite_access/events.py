"""Eve's signed change events: verify, apply once."""

from __future__ import annotations

import hashlib
import hmac
import threading
from collections import OrderedDict


def signature_ok(secret: str, body: bytes, header: str) -> bool:
    if not secret or not header:
        return False
    expected = 'sha256=' + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(header, expected)


class Dedupe:
    """At-least-once delivery means repeats: remember the last N event ids."""

    def __init__(self, size: int = 5000):
        self._seen: 'OrderedDict[int, bool]' = OrderedDict()
        self._lock = threading.Lock()
        self._size = size

    def first_time(self, event_id) -> bool:
        try:
            eid = int(event_id)
        except (TypeError, ValueError):
            return True
        with self._lock:
            if eid in self._seen:
                self._seen.move_to_end(eid)
                return False
            self._seen[eid] = True
            while len(self._seen) > self._size:
                self._seen.popitem(last=False)
        return True

    def forget(self, event_id) -> None:
        try:
            with self._lock:
                self._seen.pop(int(event_id), None)
        except (TypeError, ValueError):
            pass
