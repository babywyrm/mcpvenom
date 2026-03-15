"""AI-powered security analysis using Claude.

Layers LLM reasoning on top of deterministic checks to catch subtle
vulnerabilities that regex patterns miss: social engineering in tool
descriptions, obfuscated injection, logical attack chains, and
context-dependent risks.
"""

from mcpvenom.core.models import TargetResult
from mcpvenom.checks.base import time_check
from mcpvenom.checks.tool_probes import _build_safe_args, _call_tool, _response_text, _should_invoke


def run_llm_analysis(
    session,
    result: TargetResult,
    probe_opts: dict | None = None,
    model: str = "claude-sonnet-4-20250514",
    console=None,
):
    """Run all LLM-powered analysis phases against a scan result.

    Phase 1: Analyze tool definitions for subtle issues
    Phase 2: Analyze tool responses for embedded threats
    Phase 3: Reason about all findings to discover attack chains
    """
    from mcpvenom.core.llm import analyze_tools, analyze_findings, analyze_response

    opts = probe_opts or {}
    _log = console.print if console else lambda msg: None
    no_invoke = opts.get("no_invoke", False)

    # Phase 1: Tool description analysis
    with time_check("llm_tool_analysis", result):
        _log("  [cyan]AI analyzing tool definitions...[/cyan]")
        try:
            llm_findings = analyze_tools(result.tools, model=model)
            for f in llm_findings:
                tax = f" [{f.taxonomy_id}]" if f.taxonomy_id else ""
                result.add(
                    "llm_tool_analysis",
                    f.severity,
                    f"[AI]{tax} {f.title}",
                    f.detail,
                )
            _log(f"  [dim]  AI found {len(llm_findings)} issue(s) in tool definitions[/dim]")
        except Exception as e:
            _log(f"  [yellow]  AI tool analysis failed: {e}[/yellow]")

    # Phase 2: Response analysis (if behavioral probes are enabled)
    if not no_invoke:
        with time_check("llm_response_analysis", result):
            _log("  [cyan]AI analyzing tool responses...[/cyan]")
            response_findings = 0
            try:
                for tool in result.tools[:5]:
                    if not _should_invoke(tool, opts):
                        continue
                    name = tool.get("name", "")
                    desc = tool.get("description", "")
                    args = _build_safe_args(tool)
                    resp = _call_tool(session, name, args)
                    text = _response_text(resp)
                    if not text or len(text) < 20:
                        continue

                    llm_resp_findings = analyze_response(name, desc, text, model=model)
                    for f in llm_resp_findings:
                        tax = f" [{f.taxonomy_id}]" if f.taxonomy_id else ""
                        result.add(
                            "llm_response_analysis",
                            f.severity,
                            f"[AI]{tax} {f.title} (tool '{name}')",
                            f.detail,
                        )
                        response_findings += 1
                _log(f"  [dim]  AI found {response_findings} issue(s) in tool responses[/dim]")
            except Exception as e:
                _log(f"  [yellow]  AI response analysis failed: {e}[/yellow]")

    # Phase 3: Chain reasoning over all findings
    with time_check("llm_chain_reasoning", result):
        _log("  [cyan]AI reasoning about attack chains...[/cyan]")
        try:
            existing = [
                {"check": f.check, "severity": f.severity, "title": f.title}
                for f in result.findings
                if not f.check.startswith("llm_")
            ]
            chain_findings = analyze_findings(result.tools, existing, model=model)
            for f in chain_findings:
                tax = f" [{f.taxonomy_id}]" if f.taxonomy_id else ""
                result.add(
                    "llm_chain_reasoning",
                    f.severity,
                    f"[AI]{tax} {f.title}",
                    f.detail,
                )
            _log(f"  [dim]  AI identified {len(chain_findings)} attack chain(s)/insight(s)[/dim]")
        except Exception as e:
            _log(f"  [yellow]  AI chain reasoning failed: {e}[/yellow]")
