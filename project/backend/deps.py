"""Application-wide service container (one instance per process) + FastAPI dependencies."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from backend.config import Settings, get_settings
from backend.services.evaluation import Evaluator
from backend.services.gemini import GeminiClient
from backend.services.graph_store import GraphStore, get_graph_store
from backend.services.mitre import MitreService, get_mitre
from backend.services.mongo import DocumentStore, get_store
from backend.services.repository import EvidenceRepository
from backend.services.runner import InvestigationRunner
from backend.services.threat_intel import ThreatIntelService

log = logging.getLogger(__name__)


@dataclass
class Container:
    settings: Settings
    store: DocumentStore
    graph: GraphStore
    llm: GeminiClient
    mitre: MitreService
    runner: InvestigationRunner
    repo: EvidenceRepository
    ti: ThreatIntelService
    evaluator: Evaluator
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    seed_status: dict = field(default_factory=lambda: {"status": "idle"})


_container: Optional[Container] = None


def build_container(settings: Optional[Settings] = None) -> Container:
    global _container
    settings = settings or get_settings()
    store = get_store()
    graph = get_graph_store()
    llm = GeminiClient(settings)
    mitre = get_mitre()
    runner = InvestigationRunner(settings, store, graph, llm, mitre)
    _container = Container(settings=settings, store=store, graph=graph, llm=llm, mitre=mitre, runner=runner,
                           repo=runner.repo, ti=runner.ti, evaluator=Evaluator(store, runner))
    return _container


def get_container() -> Container:
    if _container is None:
        return build_container()
    return _container


# ------------------------------------------------------------------ auth (demo analyst account, JWT)
_bearer = HTTPBearer(auto_error=False)


def create_token(settings: Settings, username: str) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expire_minutes)
    return jwt.encode({"sub": username, "exp": exp, "role": "analyst"}, settings.jwt_secret, algorithm="HS256")


def current_user(request: Request, creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer), c: Container = Depends(get_container)) -> dict:
    """When AUTH_REQUIRED=false every request is the demo analyst; otherwise a valid JWT is required."""
    if not c.settings.auth_required:
        if creds:
            try:
                payload = jwt.decode(creds.credentials, c.settings.jwt_secret, algorithms=["HS256"])
                username = payload.get("sub")
                if username:
                    return {"username": username, "role": "analyst"}
            except JWTError:
                pass
        return {"username": c.settings.demo_analyst_username, "role": "analyst", "anonymous": True}
    if not creds:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required")
    try:
        payload = jwt.decode(creds.credentials, c.settings.jwt_secret, algorithms=["HS256"])
    except JWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or expired token")
    username = payload.get("sub")
    if not username or payload.get("role") != "analyst":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token claims")
    return {"username": username, "role": "analyst"}
