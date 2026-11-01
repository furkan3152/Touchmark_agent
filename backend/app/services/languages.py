"""Which languages a submitted agent is written in, and how much of it each analysis covers.

The pattern rules and data-flow analysis understand Python, JavaScript/TypeScript, Rust,
Go and Solidity. Agents are also written in Java, Kotlin, C#, Swift, PHP, Ruby, Dart and
others; their source is still taken in, mapped file by file by the model
(services/file_map.py) and judged by the review and its check ledger
(services/audit_ledger.py). The report says, per language, which analyses covered it, so a
quiet rule pass on a Kotlin agent is never read as a clean bill.
"""
from __future__ import annotations

from collections import Counter

#: suffix -> language. Templates (server.py.hbs) are mapped by the suffix of their stem.
LANGUAGES = {
    ".py": "Python",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".mts": "TypeScript", ".cts": "TypeScript",
    ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
    ".rs": "Rust",
    ".go": "Go",
    ".sol": "Solidity",
    ".java": "Java",
    ".kt": "Kotlin", ".kts": "Kotlin",
    ".scala": "Scala",
    ".cs": "C#",
    ".swift": "Swift",
    ".php": "PHP",
    ".rb": "Ruby",
    ".dart": "Dart",
    ".ex": "Elixir", ".exs": "Elixir",
    ".c": "C", ".h": "C",
    ".cpp": "C++", ".cc": "C++", ".hpp": "C++",
    ".move": "Move",
    ".lua": "Lua",
}

#: Languages the deterministic rules and data-flow analysis read. Python and JS/TS get
#: data flow; Rust, Go and Solidity get pattern and contract rules.
RULE_COVERAGE = {
    "Python": "data_flow", "TypeScript": "data_flow", "JavaScript": "data_flow",
    "Rust": "patterns", "Go": "patterns", "Solidity": "patterns",
}

SOURCE_SUFFIXES = tuple(LANGUAGES)


def language_of(path: str) -> str:
    name = path.lower()
    for suffix in (".hbs", ".handlebars", ".j2", ".jinja", ".jinja2", ".tmpl", ".mustache", ".ejs"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    dot = name.rfind(".")
    return LANGUAGES.get(name[dot:], "") if dot >= 0 else ""


def coverage(paths, mapped=(), examined=()) -> list[dict]:
    """Per language: files, what the rules cover, how many files the model mapped and how
    many a review pass opened. Most files first."""
    mapped, examined = set(mapped), set(examined)
    by_language: dict[str, list[str]] = {}
    for path in paths:
        language = language_of(path)
        if language:
            by_language.setdefault(language, []).append(path)
    counts = Counter({k: len(v) for k, v in by_language.items()})
    return [{"language": language, "files": count,
             "rules": RULE_COVERAGE.get(language, "none"),
             "mapped": sum(1 for p in by_language[language] if p in mapped),
             "examined": sum(1 for p in by_language[language] if p in examined)}
            for language, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]


def rules_blind_share(paths) -> float:
    """Share of source files in languages the rules do not read (0.0 .. 1.0)."""
    langs = [language_of(p) for p in paths]
    langs = [lang for lang in langs if lang]
    if not langs:
        return 0.0
    return round(sum(1 for lang in langs if lang not in RULE_COVERAGE) / len(langs), 3)
