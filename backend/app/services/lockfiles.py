"""The dependency versions a repository actually installs, per package root.

Several Stellar rules depend on a library version, not on the code alone: an x402 client
caps each payment by default only from @x402/core 2.23.0, and an MPP charge server skips
its replay check when it has no store in some releases. A range in package.json does not
say which release is installed; the lockfile does. Every lockfile in the repository is read
once at intake, and the result travels with the audit record (``raw_metadata``), so rules
use it without the files.

The record is plain JSON:

    {"importers": {"packages/sdk": {"lockfiles": ["packages/sdk/package-lock.json"],
                                    "deps": {"@x402/fetch": {"spec": "^2.17.0", "version": "2.28.0"}}}},
     "locked": {"packages/sdk/package-lock.json": {"@x402/core": ["2.28.0"]}}}

``importers`` holds each package root's direct dependencies; ``locked`` holds every version
of the watched Stellar and payment packages each lockfile installs, transitive ones included.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

_NPM_LOCKS = ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock")
_CARGO_LOCKS = ("Cargo.lock",)
_PY_LOCKS = ("poetry.lock", "uv.lock", "Pipfile.lock")
_MANIFESTS = ("package.json", "Cargo.toml", "pyproject.toml", "requirements.txt")
_SKIP_DIRS = {"node_modules", ".git", "target", "dist", "build", ".next", ".venv", "venv", "__pycache__", "vendor"}
#: Packages whose transitive versions are recorded: a rule needs @x402/core when the code
#: imports @x402/fetch, and soroban-sdk-macros arrives with soroban-sdk.
WATCHED = re.compile(r"^(?:@x402/|@stellar/|@creit\.tech/|@openzeppelin/(?:relayer|stellar)|x402|mppx$|"
                     r"passkey-kit$|soroban-|stellar-|stellar_)")


@dataclass(frozen=True)
class Resolution:
    package: str
    #: Installed versions: from a lockfile, or from an exact pin in the manifest.
    versions: tuple[str, ...]
    #: The declared range, when the package is a direct dependency.
    spec: str | None
    #: The lockfile or manifest the versions come from.
    source: str

    @property
    def locked(self) -> bool:
        return bool(self.versions)


class Lockset:
    """Lookups over the intake record. ``near`` is a repository path (a file or directory);
    the package root nearest to it decides, as the package manager would."""

    def __init__(self, data: dict | None = None):
        data = data or {}
        self.importers: dict[str, dict] = data.get("importers") or {}
        self.locked: dict[str, dict[str, list[str]]] = data.get("locked") or {}

    @classmethod
    def read(cls, root: Path) -> "Lockset":
        return cls(read_repository(Path(root)))

    def to_json(self) -> dict:
        return {"importers": self.importers, "locked": self.locked}

    def _roots_for(self, near: str) -> list[str]:
        """Package roots that contain ``near``, nearest first."""
        parts = PurePosixPath(near.strip("/")).parts if near else ()
        chain = ["/".join(parts[:i]) for i in range(len(parts), -1, -1)]
        return [d for d in chain if d in self.importers]

    def resolve(self, package: str, near: str = "") -> Resolution | None:
        roots = self._roots_for(near) or ([""] if "" in self.importers else [])
        for root in roots:
            dep = (self.importers[root].get("deps") or {}).get(package)
            if dep is None:
                continue
            spec, version = dep.get("spec"), dep.get("version")
            if version:
                return Resolution(package, (version,), spec, dep.get("source") or root)
            pinned = exact_pin(spec)
            return Resolution(package, (pinned,) if pinned else (), spec, dep.get("source") or root)
        # Not declared by the nearest root: an installed transitive dependency.
        for root in roots[:1]:
            for lock in self.importers[root].get("lockfiles") or []:
                found = (self.locked.get(lock) or {}).get(package)
                if found:
                    return Resolution(package, tuple(found), None, lock)
        return None


# ------------------------------------------------------------------ versions and ranges

_VERSION = re.compile(r"^\s*v?(\d+)(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(?:[-+][0-9A-Za-z.-]+)?\s*$")


def version_key(version: str) -> tuple[int, int, int] | None:
    m = _VERSION.match(version or "")
    if not m or any(p and not p.isdigit() for p in m.groups()):
        return None
    return tuple(int(p or 0) for p in m.groups())  # type: ignore[return-value]


def below(version: str, boundary: str) -> bool | None:
    a, b = version_key(version), version_key(boundary)
    return None if a is None or b is None else a < b


def exact_pin(spec: str | None) -> str | None:
    """'2.8.0' or '=2.8.0' (npm), '=2.8.0' (Cargo), '==2.8.0' (pip): the one version allowed."""
    m = re.fullmatch(r"\s*(?:==?)?\s*v?(\d+\.\d+\.\d+)\s*", spec or "")
    return m.group(1) if m else None


_INF = (10**9, 0, 0)


def _partial(text: str) -> tuple[tuple[int, int, int], int] | None:
    """A version that may leave minor or patch open: (lowest version, parts given)."""
    m = _VERSION.match(text)
    if not m:
        return None
    nums: list[int] = []
    for part in m.groups():
        if part is None or not part.isdigit():
            break
        nums.append(int(part))
    given = len(nums)
    nums += [0] * (3 - given)
    return (nums[0], nums[1], nums[2]), given


def _bump(v: tuple[int, int, int], at: int) -> tuple[int, int, int]:
    return (v[0] + 1, 0, 0) if at == 0 else (v[0], v[1] + 1, 0) if at == 1 else (v[0], v[1], v[2] + 1)


def _caret(v, given):
    if v[0] > 0 or given == 1:
        return _bump(v, 0)
    if v[1] > 0 or given == 2:
        return _bump(v, 1)
    return _bump(v, 2)


def _comparator(token: str, ecosystem: str) -> tuple | None:
    """One comparator as a half-open interval [lo, hi)."""
    m = re.fullmatch(r"(\^|~=|~>|~|>=|<=|>|<|==|=)?\s*(.+)", token.strip())
    if not m:
        return None
    op, rest = m.group(1) or "", m.group(2)
    if rest in {"*", "x", "X"}:
        return (0, 0, 0), _INF
    parsed = _partial(rest)
    if parsed is None:
        return None
    v, given = parsed
    if not op and ecosystem == "cargo":
        op = "^"
    if op == "^":
        return v, _caret(v, given)
    if op == "~":
        return v, _bump(v, 0 if given == 1 else 1)
    if op == "~=":  # PEP 440: ~=1.4 is >=1.4,<2; ~=1.4.2 is >=1.4.2,<1.5
        return v, _bump(v, max(0, given - 2))
    if op == "~>":
        return v, _bump(v, max(0, given - 2))
    if op == ">=":
        return v, _INF
    if op == ">":
        return _bump(v, given - 1) if given < 3 else _bump(v, 2), _INF
    if op == "<":
        return (0, 0, 0), v
    if op == "<=":
        return (0, 0, 0), _bump(v, given - 1)
    # '=', '==' or a bare version (npm): exact, or the whole family a partial version names.
    return v, _bump(v, given - 1)


def spec_intervals(spec: str, ecosystem: str = "npm") -> list[tuple] | None:
    """The versions a range admits, as half-open intervals; None when it cannot be read
    (a tag, a URL, a workspace link)."""
    spec = (spec or "").strip()
    if not spec or re.match(r"^(?:workspace:|link:|file:|git|https?:|npm:|github:|latest|next)", spec):
        return None
    out = []
    for alternative in re.split(r"\s*\|\|\s*", spec):
        hyphen = re.fullmatch(r"(\S+)\s+-\s+(\S+)", alternative)
        if hyphen:
            lo, hi = _partial(hyphen.group(1)), _partial(hyphen.group(2))
            if not lo or not hi:
                return None
            out.append((lo[0], _bump(hi[0], hi[1] - 1)))
            continue
        tokens = [t for t in re.split(r"\s*,\s*|\s+(?=[<>=^~!])", alternative) if t and not t.startswith("!=")]
        lo, hi = (0, 0, 0), _INF
        for token in tokens:
            interval = _comparator(token, ecosystem)
            if interval is None:
                return None
            lo, hi = max(lo, interval[0]), min(hi, interval[1])
        if lo < hi:
            out.append((lo, hi))
    return out


def spec_admits(spec: str, lo: str | None = None, hi: str | None = None, ecosystem: str = "npm") -> bool | None:
    """Whether the range admits some version in [lo, hi). None when the range is unreadable."""
    intervals = spec_intervals(spec, ecosystem)
    if intervals is None:
        return None
    a = version_key(lo) if lo else (0, 0, 0)
    b = version_key(hi) if hi else _INF
    return any(max(a, i[0]) < min(b, i[1]) for i in intervals)


# ------------------------------------------------------------------ reading lockfiles

def _strip_version(raw: str) -> str:
    """pnpm '2.11.0(bufferutil@4.1.0)' or v5 '2.11.0_peer' -> '2.11.0'."""
    return re.split(r"[(_]", str(raw).strip().strip("'\""), maxsplit=1)[0]


def _package_lock(text: str, rel: str) -> tuple[dict[str, str], dict[str, set[str]]]:
    """Direct versions for the importer at ``rel`` (relative to the lockfile's directory),
    and every version of each package anywhere in the tree."""
    data = json.loads(text)
    every: dict[str, set[str]] = {}
    packages = data.get("packages")
    if isinstance(packages, dict):
        nearest: dict[str, tuple[int, str]] = {}
        prefix = f"{rel}/" if rel else ""
        for key, meta in packages.items():
            if not isinstance(meta, dict) or not meta.get("version") or "node_modules/" not in key:
                continue
            owner, name = key.rsplit("node_modules/", 1)
            owner = owner.rstrip("/")
            every.setdefault(name, set()).add(str(meta["version"]))
            # Node resolution: the importer's own node_modules first, then each parent's.
            if (owner == "" or prefix.startswith(owner + "/")) and len(owner) >= nearest.get(name, (-1, ""))[0]:
                nearest[name] = (len(owner), str(meta["version"]))
        return {k: v[1] for k, v in nearest.items()}, every

    def walk(deps: dict) -> None:  # lockfileVersion 1
        for name, meta in (deps or {}).items():
            if isinstance(meta, dict):
                if meta.get("version"):
                    every.setdefault(name, set()).add(str(meta["version"]))
                walk(meta.get("dependencies") or {})
    walk(data.get("dependencies") or {})
    direct = {k: str(v["version"]) for k, v in (data.get("dependencies") or {}).items()
              if isinstance(v, dict) and v.get("version")}
    return direct, every


def _pnpm_lock(text: str, rel: str) -> tuple[dict[str, str], dict[str, set[str]]]:
    """A line reader for the parts of pnpm-lock.yaml (v5 to v9) that matter here."""
    importers: dict[str, dict[str, str]] = {}
    watched: dict[str, set[str]] = {}
    section = ""
    importer = name = None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        body = line.strip()
        if indent == 0:
            section = body.rstrip(":")
            importer = name = None
            continue
        if section == "importers":
            if indent == 2:
                importer = body.rstrip(":").strip("'\"")
                importers.setdefault(importer, {})
            elif indent == 4:
                kind = body.rstrip(":")
                name = None if kind in {"dependencies", "devDependencies", "optionalDependencies"} else "-skip-"
            elif indent == 6 and importer is not None and name != "-skip-":
                key, _, value = body.partition(":")
                key = key.strip().strip("'\"")
                if value.strip():  # v5: 'name: version'
                    importers[importer][key] = _strip_version(value)
                    name = None
                else:
                    name = key
            elif indent == 8 and importer is not None and name not in (None, "-skip-") and body.startswith("version:"):
                importers[importer][name] = _strip_version(body.split(":", 1)[1])
        elif section in {"packages", "snapshots"} and indent == 2:
            key = body.rstrip(":").strip("'\"").lstrip("/")
            m = re.match(r"^(@?[^@\s]+)[@/](\d[^()\s:_]*)", key)
            if m:
                watched.setdefault(m.group(1), set()).add(_strip_version(m.group(2)))
    direct = {k: v for k, v in importers.get(rel or ".", {}).items() if not v.startswith(("link:", "file:"))}
    return direct, watched


def _yarn_lock(text: str) -> dict[tuple[str, str], str]:
    """(name, range) -> version, for yarn classic and berry."""
    out: dict[tuple[str, str], str] = {}
    keys: list[tuple[str, str]] = []
    for line in text.splitlines():
        if line and not line.startswith((" ", "#")) and line.rstrip().endswith(":"):
            keys = []
            for entry in line.rstrip()[:-1].split(","):
                entry = entry.strip().strip('"')
                m = re.match(r"^(@?[^@]+)@(?:npm:)?(.*)$", entry)
                if m:
                    keys.append((m.group(1), m.group(2)))
        else:
            m = re.match(r'^\s+version:?\s+"?([^"\s]+)"?', line)
            if m and keys:
                for key in keys:
                    out[key] = m.group(1)
                keys = []
    return out


def _bun_lock(text: str) -> dict[str, set[str]]:
    data = json.loads(re.sub(r",(\s*[}\]])", r"\1", text))
    out: dict[str, set[str]] = {}
    for key, entry in (data.get("packages") or {}).items():
        if isinstance(entry, list) and entry and isinstance(entry[0], str):
            name, _, version = entry[0].rpartition("@")
            out.setdefault(name or key.rsplit("/", 1)[-1], set()).add(version)
    return out


def _toml_packages(text: str) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for package in tomllib.loads(text).get("package") or []:
        if isinstance(package, dict) and package.get("name") and package.get("version"):
            out.setdefault(str(package["name"]), set()).add(str(package["version"]))
    return out


def _pipfile_lock(text: str) -> dict[str, set[str]]:
    data = json.loads(text)
    out: dict[str, set[str]] = {}
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            pinned = exact_pin((meta or {}).get("version") if isinstance(meta, dict) else None)
            if pinned:
                out.setdefault(name, set()).add(pinned)
    return out


def _manifest_deps(path: Path) -> tuple[str, dict[str, str]]:
    """(ecosystem, {name: declared range}) for one manifest."""
    text = path.read_text(errors="replace")
    if path.name == "package.json":
        data = json.loads(text)
        deps: dict[str, str] = {}
        for section in ("devDependencies", "optionalDependencies", "peerDependencies", "dependencies"):
            deps.update({k: str(v) for k, v in (data.get(section) or {}).items()})
        return "npm", deps
    if path.name == "Cargo.toml":
        data = tomllib.loads(text)
        deps = {}
        tables = [data.get("dependencies"), data.get("dev-dependencies"), (data.get("workspace") or {}).get("dependencies")]
        for table in tables:
            for name, value in (table or {}).items():
                spec = value if isinstance(value, str) else (value or {}).get("version") if isinstance(value, dict) else None
                deps[(value.get("package") if isinstance(value, dict) and value.get("package") else name)] = spec or ""
        return "cargo", deps
    if path.name == "pyproject.toml":
        data = tomllib.loads(text)
        deps = {}
        for req in (data.get("project") or {}).get("dependencies") or []:
            m = re.match(r"^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*(.*?)\s*(?:;.*)?$", req)
            if m:
                deps[m.group(1).lower().replace("_", "-")] = m.group(2)
        for name, value in ((data.get("tool") or {}).get("poetry") or {}).get("dependencies", {}).items():
            spec = value if isinstance(value, str) else (value or {}).get("version", "") if isinstance(value, dict) else ""
            deps[name.lower().replace("_", "-")] = spec
        return "pypi", deps
    deps = {}
    for line in text.splitlines():
        m = re.match(r"^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*([=<>~!][^#;]*)?", line)
        if m and not line.lstrip().startswith(("#", "-")):
            deps[m.group(1).lower().replace("_", "-")] = (m.group(2) or "").strip()
    return "pypi", deps


def _walk(root: Path) -> list[Path]:
    found = []
    stack = [root]
    while stack:
        here = stack.pop()
        try:
            entries = sorted(here.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name not in _SKIP_DIRS and not entry.name.startswith("."):
                    stack.append(entry)
            elif entry.name in _MANIFESTS + _NPM_LOCKS + _CARGO_LOCKS + _PY_LOCKS and entry.stat().st_size < 30_000_000:
                found.append(entry)
    return found


def _nearest(locks: dict[str, str], directory: str, names: tuple[str, ...]) -> str | None:
    """The lockfile with one of ``names`` at or above ``directory``."""
    parts = PurePosixPath(directory).parts if directory else ()
    for i in range(len(parts), -1, -1):
        base = "/".join(parts[:i])
        for name in names:
            candidate = f"{base}/{name}" if base else name
            if candidate in locks:
                return candidate
    return None


def _versions(name: str, text: str, yarn: dict) -> dict[str, set[str]]:
    """Every version of every package one lockfile installs."""
    if name in ("package-lock.json", "npm-shrinkwrap.json"):
        return _package_lock(text, "")[1]
    if name == "pnpm-lock.yaml":
        return _pnpm_lock(text, "")[1]
    if name == "yarn.lock":
        every: dict[str, set[str]] = {}
        for (package, _), version in yarn.items():
            every.setdefault(package, set()).add(version)
        return every
    if name == "bun.lock":
        return _bun_lock(text)
    if name == "Pipfile.lock":
        return _pipfile_lock(text)
    return _toml_packages(text)


def _ordered(versions: set[str]) -> list[str]:
    return sorted(versions, key=lambda v: version_key(v) or (0, 0, 0))


def read_repository(root: Path) -> dict:
    rel = {p.relative_to(root).as_posix(): p for p in _walk(root)}
    texts: dict[str, str] = {}
    every: dict[str, dict[str, set[str]]] = {}
    yarn: dict[str, dict] = {}
    for path, p in rel.items():
        if p.name in _MANIFESTS:
            continue
        try:
            texts[path] = p.read_text(errors="replace")
            if p.name == "yarn.lock":
                yarn[path] = _yarn_lock(texts[path])
            every[path] = _versions(p.name, texts[path], yarn.get(path, {}))
        except (ValueError, OSError, tomllib.TOMLDecodeError):
            texts.pop(path, None)

    importers: dict[str, dict] = {}
    for path, p in rel.items():
        if p.name not in _MANIFESTS:
            continue
        directory = PurePosixPath(path).parent.as_posix()
        directory = "" if directory == "." else directory
        try:
            ecosystem, declared = _manifest_deps(p)
        except (ValueError, OSError, tomllib.TOMLDecodeError):
            continue
        names = _NPM_LOCKS if ecosystem == "npm" else _CARGO_LOCKS if ecosystem == "cargo" else _PY_LOCKS
        lock = _nearest(texts, directory, names)
        entry = importers.setdefault(directory, {"lockfiles": [], "deps": {}})
        resolved: dict[str, str] = {}
        if lock:
            entry["lockfiles"].append(lock)
            lock_dir = PurePosixPath(lock).parent.as_posix()
            lock_dir = "" if lock_dir == "." else lock_dir
            inner = directory[len(lock_dir):].lstrip("/") if lock_dir else directory
            name = PurePosixPath(lock).name
            if name in ("package-lock.json", "npm-shrinkwrap.json"):
                resolved = _package_lock(texts[lock], inner)[0]
            elif name == "pnpm-lock.yaml":
                resolved = _pnpm_lock(texts[lock], inner)[0]
            elif name == "yarn.lock":
                resolved = {n: yarn[lock][(n, s)] for n, s in declared.items() if (n, s) in yarn[lock]}
            else:
                flavour = "cargo" if ecosystem == "cargo" else "pypi"
                for dep, spec in declared.items():
                    versions = every[lock].get(dep) or every[lock].get(dep.replace("-", "_")) or set()
                    fitting = [v for v in versions if not spec or spec_admits(spec, v, _next_patch(v), flavour)]
                    if len(fitting) == 1:
                        resolved[dep] = fitting[0]
        for dep, spec in declared.items():
            version = resolved.get(dep)
            entry["deps"][dep] = {"spec": spec or None, "version": version or None,
                                  "source": lock if version else path}
    locked = {path: {k: _ordered(v) for k, v in versions.items() if WATCHED.match(k)}
              for path, versions in every.items()}
    return {"importers": importers, "locked": {k: v for k, v in locked.items() if v}}


def _next_patch(version: str) -> str:
    key = version_key(version)
    return f"{key[0]}.{key[1]}.{key[2] + 1}" if key else version
