"""Bellek içi + diske kalıcı depolama.

Tek süreçli MVP için yeterli: agent'lar, job'lar, badge geçmişi ve monitoring
abonelikleri JSON olarak diske yazılır, yeniden başlatmada geri yüklenir.
"""

from __future__ import annotations

import json
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
        self._save()
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
        self._save()
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
        self._save()
        return sub

    def active_subscriptions(self) -> list[MonitorSubscription]:
        return [s for s in self.subscriptions.values() if s.active]

    # ------------------------------------------------------------ persistence
    def _save(self) -> None:
        payload = {
            "agents": {k: v.model_dump(mode="json") for k, v in self.agents.items()},
            "jobs": {k: v.model_dump(mode="json") for k, v in self.jobs.items()},
            "subscriptions": {k: v.model_dump(mode="json") for k, v in self.subscriptions.items()},
        }
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False))
        tmp.replace(self.path)

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            payload = json.loads(self.path.read_text())
        except (json.JSONDecodeError, OSError):
            return
        for key, raw in (payload.get("agents") or {}).items():
            try:
                self.agents[key] = AgentArtifact.model_validate(raw)
            except Exception:
                continue
        for key, raw in (payload.get("jobs") or {}).items():
            try:
                self.jobs[key] = Job.model_validate(raw)
            except Exception:
                continue
        for key, raw in (payload.get("subscriptions") or {}).items():
            try:
                self.subscriptions[key] = MonitorSubscription.model_validate(raw)
            except Exception:
                continue

    def flush(self) -> None:
        self._save()
