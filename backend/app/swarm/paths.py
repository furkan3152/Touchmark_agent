"""Which source paths are test, mock, fixture or example code.

A path counts only when one of its directory or file-name *words* is such a word: ``tests/``,
``e2e-tests/``, ``wallet_test.go``, ``wallet.test.ts``, ``TestWallet.java`` or ``conftest.py``.
A word that merely contains one does not: ``testnet_wallet.py``, ``attestation.py``,
``latest.ts``, ``inspect.py`` and ``contest/`` are shipped code. Stellar projects name real
files ``testnet_*`` all the time, and a seed or a poisoned tool description in one of them must
not be rated as test data.
"""
from __future__ import annotations

import re

#: Words that make a directory or a file test, mock, fixture or example code.
TEST_WORDS = frozenset({
    "test", "tests", "spec", "specs", "mock", "mocks", "fixture", "fixtures", "example", "examples",
    "testdata", "e2e", "smoke", "conftest", "stories",
})
_CAMEL = re.compile(r"([a-z0-9])([A-Z])")
_SPLIT = re.compile(r"[^A-Za-z0-9]+")


def _words(part: str) -> list[str]:
    return [w.lower() for w in _SPLIT.split(_CAMEL.sub(r"\1 \2", part)) if w]


def is_testlike(path: str, *, extra_dirs: frozenset[str] | set[str] = frozenset()) -> bool:
    """True when ``path`` (``dir/file.ext``, optionally ``:line``) is test, mock, fixture or
    example code. ``extra_dirs`` adds directory names that count too (``scripts``)."""
    parts = [p for p in path.replace("\\", "/").split("/") if p]
    if not parts:
        return False
    *dirs, name = parts
    for d in dirs:
        if d.lower() in extra_dirs or any(w in TEST_WORDS for w in _words(d)):
            return True
    words = _words(name)
    if len(words) > 1:
        words = words[:-1]  # the extension is not a word of the name
    return any(w in TEST_WORDS for w in words)
