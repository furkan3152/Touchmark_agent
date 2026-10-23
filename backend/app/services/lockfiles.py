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
#: How each lockfile's ranges read: a bare Cargo version is a caret range, a bare npm one exact.
_ECOSYSTEM = {**{n: "cargo" for n in _CARGO_LOCKS}, **{n: "pypi" for n in _PY_LOCKS}}
#: Bytes of lockfiles read per repository, nearest the root first, and manifests read: a
#: repository cannot make intake parse without bound.
_LOCK_BUDGET, _MAX_MANIFESTS = 64_000_000, 2_000
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
    #: The package root (a directory with a manifest, '' for the repository root) that resolves it.
    root: str = ""

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
                return Resolution(package, (version,), spec, dep.get("source") or root, root)
            pinned = exact_pin(spec)
            if pinned:
                return Resolution(package, (pinned,), spec, dep.get("source") or root, root)
            # The importer's own entry named no version (an older lockfile layout, two locked
            # copies): a lockfile in the root's own directory still says what is installed, but
            # only versions the declared range admits stand for this root. An npm lockfile further
            # up that names no version for it (a directory that is not a workspace member, such as
            # a scaffold template) says nothing about it. A Cargo or Python lockfile further up is
            # the workspace's, which records no importers; it is read as for one admitted copy
            # (_Lock.direct). An unreadable range admits nothing.
            for lock in self.importers[root].get("lockfiles") or []:
                ecosystem = _ECOSYSTEM.get(PurePosixPath(lock).name, "npm")
                if _directory(lock) != root and ecosystem == "npm":
                    continue
                fitting = [v for v in (self.locked.get(lock) or {}).get(package) or []
                           if spec_admits(spec or "", v, _next_patch(v), ecosystem) is True]
                if fitting:
                    return Resolution(package, tuple(fitting), spec, lock, root)
            return Resolution(package, (), spec, dep.get("source") or root, root)
        # Not declared by the nearest root: an installed transitive dependency.
        for root in roots[:1]:
            for lock in self.importers[root].get("lockfiles") or []:
                found = (self.locked.get(lock) or {}).get(package)
                if found:
                    return Resolution(package, tuple(found), None, lock, root)
        return None


# ------------------------------------------------------------------ versions and ranges

#: major.minor.patch, then what follows it in any ecosystem: an npm pre-release and build
#: ('-rc.1+b'), PEP 440 parts ('.post0', 'rc1', '.dev2', a fourth number). Only the first three
#: numbers are compared, so a pre-release counts as its release, as it did for npm.
_VERSION = re.compile(r"^\s*v?(\d+)(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(?:[-+._]?[0-9A-Za-z][0-9A-Za-z.+_-]*)?\s*$")
#: Longer strings are not versions, and longer ranges are not read (a hand-written range is a few
#: dozen characters); the bounds also keep the regular expressions cheap on hostile input.
_VERSION_CHARS, _SPEC_CHARS = 128, 256


def version_key(version: str) -> tuple[int, int, int] | None:
    if not isinstance(version, str) or len(version) > _VERSION_CHARS:
        return None
    m = _VERSION.match(version)
    if not m or any(p and not p.isdigit() for p in m.groups()):
        return None
    return tuple(int(p or 0) for p in m.groups())  # type: ignore[return-value]


def below(version: str, boundary: str) -> bool | None:
    a, b = version_key(version), version_key(boundary)
    return None if a is None or b is None else a < b


def exact_pin(spec: str | None) -> str | None:
    """'2.8.0' or '=2.8.0' (npm), '=2.8.0' (Cargo), '==2.8.0' (pip): the one version allowed."""
    if not isinstance(spec, str) or len(spec) > _SPEC_CHARS:
        return None
    m = re.fullmatch(r"(?:==?)?\s*v?(\d+\.\d+\.\d+)", spec.strip())
    return m.group(1) if m else None


_INF = (10**9, 0, 0)


def _partial(text: str) -> tuple[tuple[int, int, int], int] | None:
    """A version that may leave minor or patch open: (lowest version, parts given)."""
    m = _VERSION.match(text) if len(text) <= _VERSION_CHARS else None
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
    (a tag, a URL, a workspace link, or longer than _SPEC_CHARS)."""
    spec = spec.strip() if isinstance(spec, str) and len(spec) <= _SPEC_CHARS else ""
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
    if a is None or b is None:  # a bound that is not a version: nothing can be said
        return None
    return any(max(a, i[0]) < min(b, i[1]) for i in intervals)


# ------------------------------------------------------------------ reading lockfiles
#
# Lockfiles and manifests are repository input: any of them can be malformed, of the wrong
# shape, deeply nested or huge. Every reader below type-checks what it walks, and
# read_repository skips a file it cannot read, so one bad file costs its own versions only.

def _dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _strip_version(raw: str) -> str:
    """pnpm '2.11.0(bufferutil@4.1.0)' or v5 '2.11.0_peer' -> '2.11.0'."""
    return re.split(r"[(_]", str(raw).strip().strip("'\""), maxsplit=1)[0]


@dataclass
class _Lock:
    """One lockfile, parsed once: every version it installs, and per importer what it resolves.

    ``scopes`` is, for package-lock, the versions installed under each directory's node_modules
    ('' is the lockfile's own directory); for pnpm, each importer's direct versions ('.' is the
    root); for yarn, (name, range) -> version. Cargo and Python lockfiles have no importers."""
    kind: str
    every: dict[str, set[str]]
    scopes: dict

    def direct(self, inner: str, declared: dict[str, str], ecosystem: str) -> dict[str, str]:
        """The version each dependency ``declared`` by the manifest at ``inner`` (relative to
        the lockfile's directory) resolves to, where the lockfile says."""
        if self.kind == "npm":
            # Node resolution: the importer's own node_modules first, then each parent's.
            parts = PurePosixPath(inner).parts if inner else ()
            chain = ["/".join(parts[:i]) for i in range(len(parts), -1, -1)]
            scopes = [self.scopes[d] for d in chain if d in self.scopes]
            return {dep: next(s[dep] for s in scopes if dep in s) for dep in declared if any(dep in s for s in scopes)}
        if self.kind == "pnpm":
            return {k: v for k, v in self.scopes.get(inner or ".", {}).items() if not v.startswith(("link:", "file:"))}
        if self.kind == "yarn":
            return {n: self.scopes[(n, s)] for n, s in declared.items() if (n, s) in self.scopes}
        resolved = {}
        flavour = "cargo" if ecosystem == "cargo" else "pypi"
        for dep, spec in declared.items():
            versions = self.every.get(dep) or self.every.get(dep.replace("-", "_")) or set()
            fitting = [v for v in versions if not spec or spec_admits(spec, v, _next_patch(v), flavour)]
            if len(fitting) == 1:
                resolved[dep] = fitting[0]
        return resolved


def _package_lock(text: str) -> _Lock:
    data = _dict(json.loads(text))
    every: dict[str, set[str]] = {}
    scopes: dict[str, dict[str, str]] = {}
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, meta in packages.items():
            if not isinstance(meta, dict) or not meta.get("version") or "node_modules/" not in key:
                continue
            owner, name = key.rsplit("node_modules/", 1)
            version = str(meta["version"])
            every.setdefault(name, set()).add(version)
            scopes.setdefault(owner.rstrip("/"), {})[name] = version
        return _Lock("npm", every, scopes)
    # lockfileVersion 1: a nested tree, walked with a stack (it can be as deep as the file).
    top = _dict(data.get("dependencies"))
    stack = [top]
    while stack:
        for name, meta in stack.pop().items():
            if isinstance(meta, dict):
                if meta.get("version"):
                    every.setdefault(name, set()).add(str(meta["version"]))
                stack.append(_dict(meta.get("dependencies")))
    scopes[""] = {k: str(v["version"]) for k, v in top.items() if isinstance(v, dict) and v.get("version")}
    return _Lock("npm", every, scopes)


def _pnpm_lock(text: str) -> _Lock:
    """A line reader for the parts of pnpm-lock.yaml (v5 to v9) that matter here. A
    single-project v5/v6 lockfile lists the root's dependencies at the top level, not under
    importers; they are read as the '.' importer."""
    importers: dict[str, dict[str, str]] = {}
    watched: dict[str, set[str]] = {}
    section = ""
    importer = name = None
    top_level = {"dependencies", "devDependencies", "optionalDependencies"}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        body = line.strip()
        if indent == 0:
            section = body.rstrip(":")
            importer = "." if section in top_level else None
            name = None
            if importer:
                importers.setdefault(importer, {})
            continue
        if section == "importers" or section in top_level:
            # Under importers an importer opens at 2, its sections at 4 and their entries at 6;
            # at the top level the section is the '.' importer's, and its entries sit at 2.
            shift = 0 if section == "importers" else 4
            if section == "importers" and indent == 2:
                importer = body.rstrip(":").strip("'\"")
                importers.setdefault(importer, {})
            elif section == "importers" and indent == 4:
                kind = body.rstrip(":")
                name = None if kind in top_level else "-skip-"
            elif indent == 6 - shift and importer is not None and name != "-skip-":
                key, _, value = body.partition(":")
                key = key.strip().strip("'\"")
                if value.strip():  # v5: 'name: version'
                    importers[importer][key] = _strip_version(value)
                    name = None
                else:
                    name = key
            elif (indent == 8 - shift and importer is not None and name not in (None, "-skip-")
                  and body.startswith("version:")):
                importers[importer][name] = _strip_version(body.split(":", 1)[1])
        elif section in {"packages", "snapshots"} and indent == 2:
            key = body.rstrip(":").strip("'\"").lstrip("/")
            m = re.match(r"^(@?[^@\s]+)[@/](\d[^()\s:_]*)", key)
            if m:
                watched.setdefault(m.group(1), set()).add(_strip_version(m.group(2)))
    return _Lock("pnpm", watched, importers)


def _yarn_lock(text: str) -> _Lock:
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
    every: dict[str, set[str]] = {}
    for (package, _), version in out.items():
        every.setdefault(package, set()).add(version)
    return _Lock("yarn", every, out)


def _bun_lock(text: str) -> _Lock:
    data = _dict(json.loads(re.sub(r",(\s*[}\]])", r"\1", text)))
    out: dict[str, set[str]] = {}
    for key, entry in _dict(data.get("packages")).items():
        if isinstance(entry, list) and entry and isinstance(entry[0], str):
            name, _, version = entry[0].rpartition("@")
            out.setdefault(name or key.rsplit("/", 1)[-1], set()).add(version)
    return _Lock("bun", out, {})


def _toml_packages(text: str) -> _Lock:
    out: dict[str, set[str]] = {}
    packages = tomllib.loads(text).get("package")
    for package in packages if isinstance(packages, list) else []:
        if isinstance(package, dict) and package.get("name") and package.get("version"):
            out.setdefault(str(package["name"]), set()).add(str(package["version"]))
    return _Lock("toml", out, {})


def _pipfile_lock(text: str) -> _Lock:
    data = _dict(json.loads(text))
    out: dict[str, set[str]] = {}
    for section in ("default", "develop"):
        for name, meta in _dict(data.get(section)).items():
            pinned = exact_pin(meta.get("version") if isinstance(meta, dict) else None)
            if pinned:
                out.setdefault(name, set()).add(pinned)
    return _Lock("pipfile", out, {})


def _parse_lock(name: str, text: str) -> _Lock:
    if name in ("package-lock.json", "npm-shrinkwrap.json"):
        return _package_lock(text)
    if name == "pnpm-lock.yaml":
        return _pnpm_lock(text)
    if name == "yarn.lock":
        return _yarn_lock(text)
    if name == "bun.lock":
        return _bun_lock(text)
    if name == "Pipfile.lock":
        return _pipfile_lock(text)
    return _toml_packages(text)


def _pypi_name(name: str) -> str:
    return name.lower().replace("_", "-")


def _manifest_deps(path: Path) -> tuple[str, dict[str, str]]:
    """(ecosystem, {name: declared range}) for one manifest. Entries of the wrong type
    (a list where a table belongs, a number for a range) are left out."""
    text = path.read_text(errors="replace")
    deps: dict[str, str] = {}
    if path.name == "package.json":
        data = _dict(json.loads(text))
        for section in ("devDependencies", "optionalDependencies", "peerDependencies", "dependencies"):
            deps.update({k: str(v) for k, v in _dict(data.get(section)).items()})
        return "npm", deps
    if path.name == "Cargo.toml":
        data = tomllib.loads(text)
        for table in (data.get("dependencies"), data.get("dev-dependencies"), _dict(data.get("workspace")).get("dependencies")):
            for name, value in _dict(table).items():
                value = value if isinstance(value, (str, dict)) else {}
                spec = value if isinstance(value, str) else value.get("version")
                package = value.get("package") if isinstance(value, dict) else None
                deps[package if isinstance(package, str) and package else name] = spec if isinstance(spec, str) else ""
        return "cargo", deps
    if path.name == "pyproject.toml":
        data = tomllib.loads(text)
        requirements = _dict(data.get("project")).get("dependencies")
        for req in requirements if isinstance(requirements, list) else []:
            m = re.match(r"^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*(.*?)\s*(?:;.*)?$", req) if isinstance(req, str) else None
            if m:
                deps[_pypi_name(m.group(1))] = m.group(2)
        for name, value in _dict(_dict(_dict(data.get("tool")).get("poetry")).get("dependencies")).items():
            spec = value if isinstance(value, str) else _dict(value).get("version", "")
            deps[_pypi_name(name)] = spec if isinstance(spec, str) else ""
        return "pypi", deps
    for line in text.splitlines():
        m = re.match(r"^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*([=<>~!][^#;]*)?", line)
        if m and not line.lstrip().startswith(("#", "-")):
            deps[_pypi_name(m.group(1))] = (m.group(2) or "").strip()
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
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir():
                    if entry.name not in _SKIP_DIRS and not entry.name.startswith("."):
                        stack.append(entry)
                elif entry.name in _MANIFESTS + _NPM_LOCKS + _CARGO_LOCKS + _PY_LOCKS and entry.stat().st_size < 30_000_000:
                    found.append(entry)
            except OSError:
                continue
    return found


def _nearest(locks: dict, directory: str, names: tuple[str, ...]) -> str | None:
    """The lockfile with one of ``names`` at or above ``directory``."""
    parts = PurePosixPath(directory).parts if directory else ()
    for i in range(len(parts), -1, -1):
        base = "/".join(parts[:i])
        for name in names:
            candidate = f"{base}/{name}" if base else name
            if candidate in locks:
                return candidate
    return None


def _directory(path: str) -> str:
    """The directory of a repository path, '' for the root."""
    parent = PurePosixPath(path).parent.as_posix()
    return "" if parent == "." else parent


def _ordered(versions: set[str]) -> list[str]:
    return sorted(versions, key=lambda v: version_key(v) or (0, 0, 0))


def _depth_first(path: str) -> tuple[int, str]:
    return path.count("/"), path


def read_repository(root: Path) -> dict:
    """Each lockfile is parsed once; each manifest then looks its dependencies up in the
    lockfile nearest to it. Files are taken nearest the root first, within _LOCK_BUDGET bytes
    of lockfiles and _MAX_MANIFESTS manifests."""
    rel = {p.relative_to(root).as_posix(): p for p in _walk(root)}
    locks: dict[str, _Lock] = {}
    budget = _LOCK_BUDGET
    for path in sorted((r for r, p in rel.items() if p.name not in _MANIFESTS), key=_depth_first):
        p = rel[path]
        try:
            size = p.stat().st_size
            if size > budget:
                continue
            budget -= size
            locks[path] = _parse_lock(p.name, p.read_text(errors="replace"))
        except Exception:  # noqa: BLE001 - malformed, wrong-shaped or too deeply nested: skip the file
            continue

    importers: dict[str, dict] = {}
    manifests = sorted((r for r, p in rel.items() if p.name in _MANIFESTS), key=_depth_first)[:_MAX_MANIFESTS]
    for path in manifests:
        directory = _directory(path)
        try:
            ecosystem, declared = _manifest_deps(rel[path])
        except Exception:  # noqa: BLE001 - an unreadable manifest declares nothing
            continue
        names = _NPM_LOCKS if ecosystem == "npm" else _CARGO_LOCKS if ecosystem == "cargo" else _PY_LOCKS
        lock = _nearest(locks, directory, names)
        entry = importers.setdefault(directory, {"lockfiles": [], "deps": {}})
        resolved: dict[str, str] = {}
        if lock:
            entry["lockfiles"].append(lock)
            lock_dir = _directory(lock)
            inner = directory[len(lock_dir):].lstrip("/") if lock_dir else directory
            resolved = locks[lock].direct(inner, declared, ecosystem)
        for dep, spec in declared.items():
            version = resolved.get(dep)
            entry["deps"][dep] = {"spec": spec or None, "version": version or None,
                                  "source": lock if version else path}
    locked = {path: {k: _ordered(v) for k, v in lock.every.items() if WATCHED.match(k)}
              for path, lock in locks.items()}
    return {"importers": importers, "locked": {k: v for k, v in locked.items() if v}}


def _next_patch(version: str) -> str:
    key = version_key(version)
    return f"{key[0]}.{key[1]}.{key[2] + 1}" if key else version
