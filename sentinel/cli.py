"""Sentinel CLI.

  python -m sentinel samples/access.log
  python -m sentinel samples/access.log --approve-all --out reports/r.md
  python -m sentinel samples/access.log --interactive        # approve each action
  python -m sentinel samples/access.log --json               # machine-readable
  python -m sentinel samples/incident.log --backend groq     # real LLM reasoning

Exit codes (usable in CI / cron alerting):
  0  clean window (no escalated IPs)
  1  suspicious activity escalated, nothing confirmed malicious
  2  confirmed malicious activity
  3  pipeline error
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .graph import Sentinel
from .llm import get_backend

BANNER = """\
   ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
   ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
   ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
   ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
   ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
   ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
   agentic web-log triage · LangGraph · human-in-the-loop
"""

PRIO_MARK = {"P1": "🔴", "P2": "🟠", "P3": "🟡", "P4": "⚪"}


def _print_proposals(state: dict, file=None) -> list[str]:
    """Human-readable approval brief. Writes to `file` (stderr when --json is
    active) so that machine-readable output on stdout stays pure JSON."""
    import sys as _sys
    w = (file or _sys.stdout).write
    pending = [a for a in state.get("actions", []) if a.get("approvals") == "pending"]
    w("\n" + "─" * 78 + "\n")
    w(f"  HUMAN APPROVAL REQUIRED — {len(pending)} IP(s) proposed for containment\n")
    w("─" * 78 + "\n")
    for a in pending:
        w(f"\n  {a['ip']}  (proposed actions: {len(a['proposed'])})\n")
        for act in a["proposed"]:
            rev = "reversible" if act.get("reversible") else "IRREVERSIBLE"
            w(f"    • {act['action']:<20} → {act['target']:<28} [{act['urgency']}, {rev}]\n")
            w(f"      {act['rationale']}\n")
    return [a["ip"] for a in pending]


def _ask(ips: list[str], auto: bool) -> dict[str, str]:
    if auto:
        return {ip: "approve" for ip in ips}
    if not sys.stdin.isatty():
        print("\n  (non-interactive stdin → defaulting to DEFER for all)")
        return {ip: "defer" for ip in ips}
    out = {}
    for ip in ips:
        ans = input(f"\n  Approve containment for {ip}? [y/N/a=all] ").strip().lower()
        if ans == "a":
            out.update({i: "approve" for i in ips[ips.index(ip):]})
            break
        out[ip] = "approve" if ans in {"y", "yes"} else "defer"
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="sentinel",
        description="Agentic SOC triage for web-server logs (LangGraph + deterministic rules).",
    )
    ap.add_argument("logfile", help="access log (CLF, nginx JSON-lines, or .gz)")
    ap.add_argument("--out", help="write markdown report here")
    ap.add_argument("--json", action="store_true", dest="as_json",
                    help="emit the full structured state as JSON instead of a report")
    ap.add_argument("--approve-all", action="store_true",
                    help="auto-approve every containment proposal (demo mode)")
    ap.add_argument("--interactive", action="store_true",
                    help="prompt for each containment proposal")
    ap.add_argument("--backend", help="force LLM backend: groq|openai|anthropic|ollama|local")
    ap.add_argument("--thread-id", default="run-1", help="checkpoint thread id")
    ap.add_argument("--quiet", action="store_true", help="suppress the banner and progress")
    args = ap.parse_args(argv)

    if not args.quiet:
        print(BANNER)

    if args.backend:
        import os
        os.environ["SENTINEL_BACKEND"] = args.backend
    try:
        backend = get_backend()
    except Exception as e:  # noqa: BLE001
        print(f"error: {e}", file=sys.stderr)
        return 3

    path = Path(args.logfile)
    if not path.exists():
        print(f"error: no such log file: {path}", file=sys.stderr)
        return 3

    if not args.quiet:
        print(f"  backend   : {backend.name} ({backend.model})")
        print(f"  log       : {path}")
        mode = "heuristic (no API key — deterministic agents)" if backend.name == "local" else "LLM reasoning"
        print(f"  reasoning : {mode}\n")

    try:
        pipe = Sentinel(backend=backend)
        run = pipe.run(str(path), thread_id=args.thread_id,
                       auto_approve=args.approve_all and not args.interactive,
                       out_path=args.out)
    except Exception as e:  # noqa: BLE001
        print(f"error: pipeline failed: {e}", file=sys.stderr)
        return 3

    state = run["state"]

    if run["status"] == "awaiting_approval":
        ips = _print_proposals(state, file=sys.stderr if args.as_json else None)
        if args.interactive:
            approvals = _ask(ips, auto=False)
        elif args.approve_all:
            approvals = _ask(ips, auto=True)
        else:
            approvals = {ip: "defer" for ip in ips}
            print("\n  → defaulting to DEFER (pass --approve-all or --interactive to decide)",
                  file=sys.stderr if args.as_json else sys.stdout)
        run = pipe.resume(args.thread_id, approvals, out_path=args.out)
        state = run["state"]

    if args.as_json:
        payload = {
            "status": run["status"],
            "parse_stats": state.get("parse_stats"),
            "fleet_stats": state.get("fleet_stats"),
            "triage": state.get("triage"),
            "analyses": state.get("analyses"),
            "actions": state.get("actions"),
            "critic": state.get("critic"),
            "run_meta": state.get("run_meta"),
        }
        print(json.dumps(payload, indent=2, default=str))
    else:
        print(run["report"] if not args.out else f"\n  report written to → {run['report_path']}")
        if not args.out:
            print("\n" + "─" * 78)
            print("  (tip: use --out to save this report, --json for structured output)")

    esc = state.get("escalations", [])
    if any(e["verdict"] == "malicious" for e in esc):
        return 2
    if esc:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
