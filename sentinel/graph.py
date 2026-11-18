"""The LangGraph pipeline.

        START
          │
        ingest ──────────────(parse CLF/JSON, count malformed)
          │
        detect ──────────────(13 deterministic rules → per-IP profiles)
          │
        triage ──────────────(TriageAgent: rank, dismiss, priorities)
          │
     ┌────┴────┐                    fan-out: one analyst per escalated IP
   analyst  analyst  analyst ...    (parallel branches in the same superstep)
     └────┬────┘
       responder ───────────(risk gate; propose containment)
          │
       respond ──── human-in-the-loop interrupt() ──── resume with approvals
          │
       report ─────────────(ReportAgent or deterministic renderer)
          │
        critic ──(high-severity issue & attempts < 2)──┐
          │                                            │
         END ◄──────────────────────────────────── revise (bounded loop)

Why the shape matters:
  * analysis fans out per-IP so a slow model doesn't serialise 6 investigations
  * the interrupt() checkpoint means a run can sit for hours awaiting an
    approval and resume exactly where it stopped
  * the critic loop is bounded so the graph always terminates
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from .agents import (AnalystAgent, CriticAgent, ReportAgent, ResponderAgent,
                     TriageAgent, build_report_context)
from .llm import get_backend
from .models import LogRecord, PipelineState
from .parser import parse_logs
from .render import render_fallback_report
from .rules import build_profiles

MAX_CRITIC_ROUNDS = 2


class Sentinel:
    """Compiled pipeline, reusable across runs (thread_id == run id)."""

    def __init__(self, backend=None):
        self.backend = backend or get_backend()
        self.triage_agent = TriageAgent(self.backend)
        self.analyst_agent = AnalystAgent(self.backend)
        self.responder_agent = ResponderAgent(self.backend)
        self.report_agent = ReportAgent(self.backend)
        self.critic_agent = CriticAgent(self.backend)
        self._records: list[LogRecord] = []
        self.checkpointer = InMemorySaver()
        self.graph = self._build()

    # ------------------------------------------------------------------ #
    # Nodes
    # ------------------------------------------------------------------ #
    def _ingest(self, state: PipelineState) -> dict:
        records, stats = parse_logs(state["log_path"], state.get("log_format", "auto"))
        self._records = records          # kept out of state: it can be huge
        return {"records": [], "parse_stats": stats, "records_n": len(records)}

    def _detect(self, state: PipelineState) -> dict:
        profiles, fleet = build_profiles(self._records)
        return {
            "profiles": [p.to_dict() for p in profiles],
            "fleet_stats": fleet,
        }

    def _triage(self, state: PipelineState) -> dict:
        triage = self.triage_agent.run(state["profiles"], state["fleet_stats"])
        return {"triage": triage, "escalations": triage.get("escalate", [])}

    def _analyst(self, state: PipelineState) -> dict:
        # Runs once per escalated IP via Send fan-out; the item arrives in state.
        esc = state["_item"]
        profile = next(p for p in state["profiles"] if p["ip"] == esc["ip"])
        samples = self._raw_samples(profile["ip"], limit=30)
        analysis = self.analyst_agent.run(profile, samples, esc.get("reason", ""))
        analysis["ip"] = profile["ip"]
        analysis["verdict"] = profile["verdict"]
        analysis["risk_score"] = profile["risk_score"]
        analysis["priority"] = esc["priority"]
        return {"analyses": [analysis]}

    def _raw_samples(self, ip: str, limit: int = 30) -> list[dict]:
        """Representative raw lines for one IP: first few, last few, and the
        single highest-signal request (hostile payload if present)."""
        recs = [r for r in self._records if r.ip == ip]
        if not recs:
            return []
        hostile = [r for r in recs if any(t in r.path.lower() for t in
                   ("union", "select", "../", "<script", "passwd", ".env", "wp-login", "sleep("))]
        picked = recs[:8] + hostile[:6] + recs[-8:]
        seen, out = set(), []
        for r in picked:
            key = (r.ts, r.path)
            if key in seen:
                continue
            seen.add(key)
            out.append(r.to_dict())
        return out[:limit]

    def _responder(self, state: PipelineState) -> dict:
        proposals = []
        for a in state.get("analyses", []):
            profile = next(p for p in state["profiles"] if p["ip"] == a["ip"])
            proposals.append(self.responder_agent.run(profile, a))
        return {"actions": [{**p, "approvals": "pending" if not p["gated"] else "n/a"} for p in proposals]}

    def _respond(self, state: PipelineState) -> dict:
        """Human-in-the-loop gate. interrupt() suspends the graph here."""
        pending = [a for a in state["actions"] if a.get("approvals") == "pending"]
        if not pending:
            return {}
        decision = interrupt({
            "kind": "containment_approval",
            "summary": f"{len(pending)} containment proposal(s) await approval",
            "proposals": [
                {"ip": a["ip"], "gated": a["gated"], "actions": a["proposed"]}
                for a in pending
            ],
        })
        approvals = decision.get("approvals", decision) if isinstance(decision, dict) else {}
        updated = []
        for a in state["actions"]:
            if a.get("approvals") != "pending":
                updated.append(a)
                continue
            choice = str(approvals.get(a["ip"], "defer")).lower()
            approved = choice in {"approve", "approved", "yes", "y"}
            updated.append({
                **a,
                "approvals": "approved" if approved else "deferred",
                "executed": self._execute(a) if approved else [],
            })
        return {"actions": updated, "approvals": approvals}

    def _execute(self, proposal: dict) -> list[dict]:
        """Dry-run executor: writes a change-plan instead of touching real infra.

        Swap this for webhook/API calls to your WAF/firewall in production;
        keeping it explicit and logged is what makes the pipeline auditable.
        """
        plan = []
        for act in proposal.get("proposed", []):
            plan.append({
                "action": act["action"],
                "target": act["target"],
                "mode": "dry-run",
                "status": "planned",
                "would_call": f"edge-api://{act['action']}?target={act['target']}",
            })
        return plan

    def _report(self, state: PipelineState) -> dict:
        ctx = build_report_context(state)
        md = self.report_agent.run(ctx)
        if not md:
            md = render_fallback_report(state)
            source = "deterministic-renderer"
        else:
            source = self.backend.name
        return {"report_markdown": md,
                "run_meta": {**state.get("run_meta", {}), "report_source": source}}

    def _critic(self, state: PipelineState) -> dict:
        """Adversarial review runs BEFORE the report is written, so its findings
        are incorporated rather than bolted on afterwards."""
        ctx = build_report_context(state)
        critique = self.critic_agent.run(ctx, state.get("triage", {}), state.get("analyses", []))
        return {"critic": critique}

    # ------------------------------------------------------------------ #
    # Routing
    # ------------------------------------------------------------------ #
    def _fan_out(self, state: PipelineState) -> list:
        from langgraph.types import Send

        esc = state.get("escalations", [])[:8]
        if not esc:
            return ["responder"]          # nothing to analyse; skip to response
        # NOTE: Send() snapshots the state it is given. Passing minified state here
        # keeps the per-branch payload small; the analyst node needs profiles too,
        # so we send the keys it actually reads.
        payload_for = lambda item: {
            "profiles": state.get("profiles", []),
            "log_path": state.get("log_path", ""),
            "run_meta": state.get("run_meta", {}),
            "_item": item,
        }
        return [Send("analyst", payload_for(e)) for e in esc]

    def _after_report(self, state: PipelineState) -> str:
        critique = state.get("critic", {})
        rounds = state.get("run_meta", {}).get("critic_rounds", 0)
        high = [i for i in critique.get("issues", []) if i.get("severity") == "high"]
        if high and rounds < MAX_CRITIC_ROUNDS:
            return "revise"
        return END

    def _revise(self, state: PipelineState) -> dict:
        """One bounded correction pass: append critic findings as an addendum."""
        critique = state.get("critic", {})
        lines = ["\n\n---\n\n## Reviewer addendum (automated critic, unedited)\n"]
        for i in critique.get("issues", []):
            lines.append(f'- **[{i["severity"].upper()}]** {i["finding"]} — _{i["fix"]}_')
        md = state["report_markdown"] + "\n".join(lines)
        rounds = state.get("run_meta", {}).get("critic_rounds", 0) + 1
        return {"report_markdown": md,
                "run_meta": {**state.get("run_meta", {}), "critic_rounds": rounds}}

    # ------------------------------------------------------------------ #
    # Graph assembly
    # ------------------------------------------------------------------ #
    def _build(self):
        g = StateGraph(PipelineState)
        g.add_node("ingest", self._ingest)
        g.add_node("detect", self._detect)
        g.add_node("triage", self._triage)
        g.add_node("analyst", self._analyst)
        g.add_node("responder", self._responder)
        g.add_node("respond", self._respond)
        g.add_node("report", self._report)
        g.add_node("critic", self._critic)
        g.add_node("revise", self._revise)

        g.add_edge(START, "ingest")
        g.add_edge("ingest", "detect")
        g.add_edge("detect", "triage")
        g.add_conditional_edges("triage", self._fan_out, ["analyst", "responder"])
        g.add_edge("analyst", "responder")
        g.add_edge("responder", "respond")
        g.add_edge("respond", "critic")
        g.add_edge("critic", "report")
        g.add_conditional_edges("report", self._after_report, ["revise", END])
        g.add_edge("revise", END)
        return g.compile(checkpointer=self.checkpointer)

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def run(self, log_path: str, thread_id: str = "run-1", auto_approve: bool = False,
            out_path: str | None = None) -> dict:
        """Run to (and through) the human approval gate."""
        config = {"configurable": {"thread_id": thread_id}}
        initial = {
            "log_path": str(log_path),
            "log_format": "auto",
            "records": [], "profiles": [], "analyses": [], "escalations": [],
            "actions": [], "notes": [], "run_meta": {"backend": self.backend.name},
        }
        result = self.graph.invoke(initial, config)
        if "__interrupt__" in result:
            if not auto_approve:
                return {"status": "awaiting_approval", "interrupt": result["__interrupt__"],
                        "state": result, "thread_id": thread_id}
            from langgraph.types import Command

            pending = [a for a in result.get("actions", []) if a.get("approvals") == "pending"]
            decision = {a["ip"]: "approve" for a in pending}
            result = self.graph.invoke(Command(resume={"approvals": decision}), config)

        md = result.get("report_markdown", "")
        report_path = None
        if out_path:
            p = Path(out_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(md, encoding="utf-8")
            report_path = str(p)
        return {"status": "complete", "state": result, "report": md,
                "report_path": report_path, "thread_id": thread_id}

    def resume(self, thread_id: str, approvals: dict[str, str], out_path: str | None = None) -> dict:
        """Resume a suspended run with {ip: 'approve'|'defer'}."""
        from langgraph.types import Command

        config = {"configurable": {"thread_id": thread_id}}
        result = self.graph.invoke(Command(resume={"approvals": approvals}), config)
        md = result.get("report_markdown", "")
        report_path = None
        if out_path:
            p = Path(out_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(md, encoding="utf-8")
            report_path = str(p)
        return {"status": "complete", "state": result, "report": md, "report_path": report_path}
