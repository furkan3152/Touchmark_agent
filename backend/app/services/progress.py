"""Stage events for a long audit, so a streaming response can show where it is.

A callback is set for the duration of one request (a context variable, so concurrent audits
never see each other's events); code anywhere in the audit calls ``emit``. Without a
callback ``emit`` does nothing, so the non-streaming path and the CLI are unchanged.

Stages, in order: ``resolving``, ``fetching``, ``rules``, ``deep_review`` (with
``files_read``/``files_total``), ``verifier`` (with ``checked``/``total``), ``done``.
"""

from __future__ import annotations

import contextvars
from typing import Callable

_listener: contextvars.ContextVar[Callable[[dict], None] | None] = contextvars.ContextVar("touchmark_progress",
                                                                                           default=None)
STAGES = ("resolving", "fetching", "rules", "deep_review", "verifier", "done")


def listen(callback: Callable[[dict], None] | None) -> contextvars.Token:
    return _listener.set(callback)


def stop(token: contextvars.Token) -> None:
    _listener.reset(token)


def emit(stage: str, **info) -> None:
    callback = _listener.get()
    if callback is None:
        return
    try:
        callback({"stage": stage, **info})
    except Exception:  # noqa: BLE001 - reporting progress must never break the audit
        pass
