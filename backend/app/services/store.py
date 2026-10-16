"""Bellek içi + diske kalıcı depolama.

Tek süreçli MVP için yeterli: agent'lar, job'lar, badge geçmişi ve monitoring
abonelikleri JSON olarak diske yazılır, yeniden başlatmada geri yüklenir.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from ..config import Settings
from ..models import AgentArtifact, Job, MonitorSubscription


class Store:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._lock = threading.Lock()
        self.agents: dict[str, AgentArtifact] = {}
        self.jobs: dict[str, Job] = {}
        self.subscriptions: dict[str, MonitorSubscription] = {}
        self._load()

    # ------------------------------------------------------------------ paths
    @property
    def path(self) -> Path:
        return self.settings.data_path / "state.json"

    # ------------------------------------------------------------------ agents
    def put_agent(self, artifact: AgentArtifact) -> AgentArtifact:
        with self._lock:
            self.agents[artifact.id] = artifact
            self._save_locked()
        return artifact

    def get_agent(self, agent_id: str) -> AgentArtifact | None:
        return self.agents.get(agent_id)

    def find_agent_by_wallet(self, wallet: str) -> AgentArtifact | None:
        wallet_l = wallet.lower()
        for a in self.agents.values():
            if a.agent_wallet.lower() == wallet_l:
                return a
        return None

    # -------------------------------------------------------------------- jobs
    def put_job(self, job: Job) -> Job:
        with self._lock:
            self.jobs[job.id] = job
            self._save_locked()
        return job

    def get_job(self, job_id: str) -> Job | None:
        return self.jobs.get(job_id)

    def jobs_for_agent(self, agent_id: str) -> list[Job]:
        return sorted(
            (j for j in self.jobs.values() if j.agent_id == agent_id),
            key=lambda j: j.created_at,
            reverse=True,
        )

    def recent_jobs(self, limit: int = 20) -> list[Job]:
        return sorted(self.jobs.values(), key=lambda j: j.created_at, reverse=True)[:limit]

    # ----------------------------------------------------------- subscriptions
    def put_subscription(self, sub: MonitorSubscription) -> MonitorSubscription:
        with self._lock:
            self.subscriptions[sub.id] = sub
            self._save_locked()
        return sub

    def active_subscriptions(self) -> list[MonitorSubscription]:
        return [s for s in self.subscriptions.values() if s.active]

    # ------------------------------------------------------------ persistence
    @property
    def backup_path(self) -> Path:
        return self.path.with_name("state.json.bak")

    def _save_locked(self) -> None:
        """Atomik, fsync'li ve owner-only kayıt; çağıran ``self._lock`` tutmalıdır.

        Önceki sürüm ``state.json.bak`` olarak saklanır. Doğrulanamayan kayıtlar
        silinmez, ham hâlleriyle geri yazılır.
        """
        payload = {}
        for section, items in (("agents", self.agents), ("jobs", self.jobs),
                               ("subscriptions", self.subscriptions)):
            payload[section] = {**self._unparsed.get(section, {}),
                                **{k: v.model_dump(mode="json") for k, v in items.items()}}
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        if self.path.exists():
            os.replace(self.path, self.backup_path)
        os.replace(tmp, self.path)
        try:
            dir_fd = os.open(self.path.parent, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    def _read(self, path: Path) -> dict | None:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError, UnicodeDecodeError):
            return None
        return payload if isinstance(payload, dict) else None

    def _load(self) -> None:
        self._unparsed: dict[str, dict] = {}
        candidates = [p for p in (self.path, self.backup_path) if p.exists()]
        if not candidates:
            return
        payload = next((data for data in map(self._read, candidates) if data is not None), None)
        if payload is None:
            # Never start empty over unreadable state: the next write would erase it.
            raise RuntimeError(f"Operator state at {self.path} and its backup are unreadable; "
                               "restore or move them before starting.")
        for section, model, target in (("agents", AgentArtifact, self.agents), ("jobs", Job, self.jobs),
                                       ("subscriptions", MonitorSubscription, self.subscriptions)):
            for key, raw in (payload.get(section) or {}).items():
                try:
                    target[key] = model.model_validate(raw)
                except Exception:
                    self._unparsed.setdefault(section, {})[key] = raw

    def flush(self) -> None:
        with self._lock:
            self._save_locked()
