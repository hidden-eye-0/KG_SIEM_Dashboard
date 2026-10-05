"""Central configuration.

All secrets and tunables come from environment variables / `.env` (pydantic-settings).
Nothing here is ever sent to the frontend except through `public_dict()`, which
deliberately strips secrets.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env", env_file_encoding="utf-8", extra="ignore"
    )

    # ---- LLM
    gemini_api_key: Optional[str] = Field(default=None, alias="GEMINI_API_KEY")
    gemini_model: str = Field(default="gemini-2.5-flash", alias="GEMINI_MODEL")

    # ---- Threat intelligence (optional)
    virustotal_api_key: Optional[str] = Field(default=None, alias="VIRUSTOTAL_API_KEY")
    otx_api_key: Optional[str] = Field(default=None, alias="OTX_API_KEY")
    ti_cache_ttl_seconds: int = Field(default=6 * 3600, alias="TI_CACHE_TTL_SECONDS")

    # ---- Databases (empty -> in-process fallbacks)
    mongodb_uri: Optional[str] = Field(default=None, alias="MONGODB_URI")
    mongodb_db: str = Field(default="siem_kg", alias="MONGODB_DB")
    neo4j_uri: Optional[str] = Field(default=None, alias="NEO4J_URI")
    neo4j_username: str = Field(default="neo4j", alias="NEO4J_USERNAME")
    neo4j_password: Optional[str] = Field(default=None, alias="NEO4J_PASSWORD")

    # ---- Investigation safeguards
    max_investigation_steps: int = Field(default=12, alias="MAX_INVESTIGATION_STEPS")
    max_events_per_query: int = Field(default=500, alias="MAX_EVENTS_PER_QUERY")
    max_time_window_seconds: int = Field(default=86400, alias="MAX_TIME_WINDOW_SECONDS")
    max_graph_nodes: int = Field(default=300, alias="MAX_GRAPH_NODES")
    max_llm_calls_per_investigation: int = Field(default=20, alias="MAX_LLM_CALLS_PER_INVESTIGATION")
    max_ti_lookups_per_investigation: int = Field(default=10, alias="MAX_TI_LOOKUPS_PER_INVESTIGATION")
    investigation_timeout_seconds: int = Field(default=300, alias="INVESTIGATION_TIMEOUT_SECONDS")
    investigation_policy: str = Field(default="llm", alias="INVESTIGATION_POLICY")  # llm | heuristic
    sufficiency_threshold: float = Field(default=0.8, alias="SUFFICIENCY_THRESHOLD")

    # ---- Data / ML
    dataset_dir: Path = Field(default=PROJECT_ROOT / "data" / "raw", alias="DATASET_DIR")
    processed_dir: Path = Field(default=PROJECT_ROOT / "data" / "processed", alias="PROCESSED_DIR")
    reports_dir: Path = Field(default=PROJECT_ROOT / "data" / "reports", alias="REPORTS_DIR")
    artifacts_dir: Path = Field(default=PROJECT_ROOT / "ml" / "artifacts", alias="ARTIFACTS_DIR")
    scenarios_dir: Path = Field(default=PROJECT_ROOT / "data" / "scenarios", alias="SCENARIOS_DIR")
    subset_max_per_class: int = Field(default=100_000, alias="SUBSET_MAX_PER_CLASS")
    random_seed: int = Field(default=42, alias="RANDOM_SEED")
    demo_flows_per_class: int = Field(default=600, alias="DEMO_FLOWS_PER_CLASS")

    # ---- App
    api_host: str = Field(default="0.0.0.0", alias="API_HOST")
    api_port: int = Field(default=8000, alias="API_PORT")
    frontend_origin: str = Field(default="http://localhost:5173", alias="FRONTEND_ORIGIN")
    jwt_secret: str = Field(default="change-me-in-production", alias="JWT_SECRET")
    jwt_expire_minutes: int = Field(default=12 * 60, alias="JWT_EXPIRE_MINUTES")
    demo_analyst_username: str = Field(default="analyst", alias="DEMO_ANALYST_USERNAME")
    demo_analyst_password: str = Field(default="analyst", alias="DEMO_ANALYST_PASSWORD")
    auth_required: bool = Field(default=False, alias="AUTH_REQUIRED")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    auto_seed_demo: bool = Field(default=True, alias="AUTO_SEED_DEMO")

    # ---- derived helpers -------------------------------------------------
    @property
    def gemini_configured(self) -> bool:
        return bool(self.gemini_api_key)

    @property
    def mongo_configured(self) -> bool:
        return bool(self.mongodb_uri)

    @property
    def neo4j_configured(self) -> bool:
        return bool(self.neo4j_uri and self.neo4j_password)

    @property
    def effective_policy(self) -> str:
        if self.investigation_policy == "llm" and not self.gemini_configured:
            return "heuristic"
        return self.investigation_policy

    def cors_origins(self) -> List[str]:
        origins = {self.frontend_origin, "http://localhost:5173", "http://127.0.0.1:5173"}
        return sorted(o for o in origins if o)

    def public_dict(self) -> dict:
        """Non-secret configuration exposed to the UI."""
        return {
            "gemini_model": self.gemini_model,
            "gemini_configured": self.gemini_configured,
            "virustotal_configured": bool(self.virustotal_api_key),
            "otx_configured": bool(self.otx_api_key),
            "mongo_backend": "mongodb" if self.mongo_configured else "in-process (mongomock)",
            "graph_backend": "neo4j" if self.neo4j_configured else "in-memory (networkx)",
            "investigation_policy_requested": self.investigation_policy,
            "investigation_policy_effective": self.effective_policy,
            "budget": {
                "max_investigation_steps": self.max_investigation_steps,
                "max_events_per_query": self.max_events_per_query,
                "max_time_window_seconds": self.max_time_window_seconds,
                "max_graph_nodes": self.max_graph_nodes,
                "max_llm_calls_per_investigation": self.max_llm_calls_per_investigation,
                "max_ti_lookups_per_investigation": self.max_ti_lookups_per_investigation,
                "investigation_timeout_seconds": self.investigation_timeout_seconds,
                "sufficiency_threshold": self.sufficiency_threshold,
            },
            "dataset_dir": str(self.dataset_dir),
            "processed_dir": str(self.processed_dir),
            "artifacts_dir": str(self.artifacts_dir),
            "random_seed": self.random_seed,
            "auth_required": self.auth_required,
        }


@lru_cache
def get_settings() -> Settings:
    return Settings()
