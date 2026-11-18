"""Shared data model for the Sentinel pipeline.

Everything that flows between graph nodes is a plain dataclass or dict so the
whole project runs with zero external services (no LLM key required) and is
still trivially swappable for a real model later (see sentinel/llm.py).
"""

from __future__ import annotations

import operator
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Annotated, Any, TypedDict


# --------------------------------------------------------------------------- #
# Parsed log record
# --------------------------------------------------------------------------- #
@dataclass
class LogRecord:
    ip: str
    ts: datetime
    method: str
    path: str
    status: int
    size: int
    user_agent: str
    referer: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["ts"] = self.ts.isoformat()
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "LogRecord":
        d = dict(d)
        d["ts"] = datetime.fromisoformat(d["ts"])
        return cls(**d)


# --------------------------------------------------------------------------- #
# Findings / signals
# --------------------------------------------------------------------------- #
@dataclass
class Signal:
    """One detected bot-like or hostile pattern for a single IP."""

    rule_id: str            # e.g. "SCAN-001"
    title: str              # short human label
    severity: str           # low | medium | high | critical
    score: int              # points contributed to the IP's risk score
    evidence: list[str]     # concrete lines / facts supporting the finding
    mitre: str = ""         # rough ATT&CK mapping, e.g. T1595 Active Scanning
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Per-IP aggregated behaviour (analyst agent input)
# --------------------------------------------------------------------------- #
@dataclass
class IpProfile:
    ip: str
    requests: int = 0
    first_seen: str = ""
    last_seen: str = ""
    span_seconds: float = 0.0
    req_per_min_peak: float = 0.0
    unique_paths: int = 0
    error_4xx: int = 0
    status_histogram: dict[str, int] = field(default_factory=dict)
    methods: dict[str, int] = field(default_factory=dict)
    user_agents: list[str] = field(default_factory=list)
    top_paths: list[str] = field(default_factory=list)
    auth_failures: int = 0
    compromised_identity: str = ""   # identity used on a successful auth after failures
    signals: list[Signal] = field(default_factory=list)
    risk_score: int = 0
    verdict: str = "benign"     # benign | suspicious | malicious
    confidence: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------- #
# LangGraph state
# --------------------------------------------------------------------------- #
class PipelineState(TypedDict, total=False):
    # inputs
    log_path: str
    window_minutes: int
    log_format: str

    # parse stage
    records: list[dict[str, Any]]       # LogRecord.to_dict()
    parse_stats: dict[str, Any]

    # detection stage
    profiles: list[dict[str, Any]]      # IpProfile.to_dict()
    fleet_stats: dict[str, Any]

    # analysis stage
    # reducer: parallel Send() analyst branches each append their own note
    analyses: Annotated[list[dict[str, Any]], operator.add]

    # triage / gating stage
    escalations: list[dict[str, Any]]
    triage: dict[str, Any]

    # response stage
    approvals: dict[str, Any]           # filled by human-in-the-loop interrupt
    actions: list[dict[str, Any]]

    # reporting stage
    report_markdown: str
    report_path: str
    run_meta: dict[str, Any]

    # critic stage
    critic: dict[str, Any]

    # control
    error: str
    notes: list[str]
    records_n: int
    _item: dict[str, Any]     # Send() payload for the per-IP analyst fan-out
