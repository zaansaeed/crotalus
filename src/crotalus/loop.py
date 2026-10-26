"""The run-forever loop shared by the poller, the worker and the triager.

Each of them is one `step` function, repeated:

    poller   poll_once                      fetch the feed, store new releases
    worker   analyze_next_release           rules on one pending release
    triager  triage_next_flagged_release    LLM on one flagged release

A step returns True if it did something and False if there was nothing to do,
which decides how long to sleep before the next one.

Errors in `retry_later_on` (PyPI or Gemini unreachable or rate-limiting) mean "not
now": the step has already rolled back, so the loop waits and tries again. Any other
error stops the loop, so the problem gets looked at. Ctrl+C stops it too; a step
interrupted mid-transaction rolls back, so nothing is left half done.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from crotalus.db import Connection, connect


def run_forever(
    name: str,
    step: Callable[[Connection], bool],
    *,
    sleep_after_work: float,
    sleep_when_idle: float,
    retry_later_on: tuple[type[Exception], ...] = (),
    sleep_before_retry: float = 60,
) -> None:
    print(f"{name} started. Ctrl+C to stop.")
    try:
        # One connection for the whole run. autocommit: nothing is held open between
        # steps; each step opens its own transaction (`with conn.transaction()`).
        with connect() as conn:
            conn.autocommit = True
            while True:
                try:
                    did_work = step(conn)
                except retry_later_on as exc:
                    print(f"{name}: {exc}; retrying in {sleep_before_retry:.0f}s")
                    time.sleep(sleep_before_retry)
                    continue
                time.sleep(sleep_after_work if did_work else sleep_when_idle)
    except KeyboardInterrupt:
        print(f"{name} stopped.")
