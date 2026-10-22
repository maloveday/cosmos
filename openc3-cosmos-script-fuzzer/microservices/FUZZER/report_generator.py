"""
report_generator.py - Robot Framework-style, single-file HTML report.

SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any, Dict

from jinja2 import Environment, select_autoescape


def _fmt_elapsed(seconds: float) -> str:
    seconds = max(0.0, float(seconds or 0))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{int(h):02d}:{int(m):02d}:{s:06.3f}"


TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="OpenC3 COSMOS Script Fuzzer execution report for {{ script_name }}">
<title>{{ script_name }} Fuzz Report</title>
<style>
:root{--pass:#97bd61;--fail:#ce3e01;--warn:#fed84f;--skip:#fed84f;--border:#ccc;--hdr:#ddd;--txt:#000;--muted:#666}
*{box-sizing:border-box}
body{margin:0;font-family:Helvetica,Arial,sans-serif;font-size:14px;color:var(--txt);
 background:{{ 'var(--pass)' if summary.failed == 0 else 'var(--fail)' }};padding:0 10px 40px}
#container{background:#fff;max-width:1400px;margin:0 auto;padding:6px 16px 20px;border-radius:0 0 6px 6px;box-shadow:0 2px 10px rgba(0,0,0,.25)}
#header{display:flex;justify-content:space-between;align-items:flex-end;border-bottom:1px solid var(--border);padding:8px 0}
h1{margin:0;font-size:2em;letter-spacing:-.5px}
h2{font-size:1.3em;margin:24px 0 8px;padding-bottom:3px;border-bottom:1px solid var(--border)}
#generated{text-align:right;color:var(--muted);font-size:.9em}
table{border-collapse:collapse;width:100%}
th,td{border:1px solid var(--border);padding:4px 7px;text-align:left;vertical-align:top}
th{background:var(--hdr);font-weight:bold}
table.info th{width:200px;background:#f2f2f2}
.pass{color:#3c763d}.fail{color:var(--fail)}.warn{color:#8a6d00}
.label{display:inline-block;padding:1px 6px;border-radius:3px;font-size:.78em;font-weight:bold;color:#fff;min-width:44px;text-align:center}
.label.pass,.label.PASS{background:var(--pass)}.label.fail,.label.FAIL{background:var(--fail)}
.label.warn,.label.WARN{background:var(--warn);color:#000}
.label.kw{background:#999}.label.test{background:#4d6fb0}.label.evt{background:#7a3fb0}
.graph{position:relative;height:16px;width:100%;min-width:200px;border:1px solid var(--border);background:#eee;border-radius:2px;overflow:hidden;display:flex}
.graph b{display:block;height:100%}.graph .p{background:var(--pass)}.graph .f{background:var(--fail)}
.num{text-align:right;font-variant-numeric:tabular-nums}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px}
.card{border:1px solid var(--border);border-radius:4px;padding:10px 12px;background:#fafafa}
.card .v{font-size:1.9em;font-weight:bold;margin-top:4px}.card .s{color:var(--muted);font-size:.85em}
.meter{height:8px;background:#e5e5e5;border-radius:4px;overflow:hidden;margin-top:6px}
.meter i{display:block;height:100%;background:var(--pass)}
.toolbar{margin:6px 0}
button{font:inherit;font-size:.85em;padding:3px 10px;border:1px solid #999;background:#f4f4f4;border-radius:3px;cursor:pointer}
button:hover{background:#e4e4e4}
.element{border:1px solid var(--border);margin:4px 0;background:#fff}
.element-header{display:flex;gap:8px;align-items:center;padding:4px 8px;cursor:pointer;background:#f7f7f7;user-select:none}
.element-header:hover{background:#eef}
.element-header .tog{font-family:monospace;width:12px;color:var(--muted)}
.element-header .name{font-weight:bold;flex:1}
.element-header .el{color:var(--muted);font-size:.85em}
.children{display:none;padding:6px 10px 8px 26px}
.element.open>.children{display:block}
.steps td{font-family:Consolas,monospace;font-size:.85em}
.steps tr.FAIL td{background:#fbe5dc}.steps tr.WARN td{background:#fff7d6}
.newpath{color:#2a7ae2;font-weight:bold}
pre{background:#fbe5dc;border:1px solid #e3b5a2;padding:8px;overflow:auto;font-size:.85em;margin:6px 0}
.msg{margin:4px 0}
.src{font-family:Consolas,monospace;font-size:.82em;white-space:pre}
.src td{border:none;padding:0 8px}.src td.ln{color:#999;text-align:right;width:1%;user-select:none}
.src tr.run td.code{background:#e6f4d7}.src tr.mis td.code{background:#fbe0d5}.src tr.par td.code{background:#fff1b8}
svg .area{fill:rgba(151,189,97,.25)}svg .l1{stroke:#5a8f29;fill:none;stroke-width:2}svg .l2{stroke:#2a7ae2;fill:none;stroke-width:2;stroke-dasharray:4 3}
.legend span{margin-right:14px;font-size:.85em}
</style>
</head>
<body>
<div id="container">
<header id="header">
  <h1>{{ script_name }} Fuzz Report</h1>
  <div id="generated">Generated<br>{{ generated }}</div>
</header>

<main>
<section>
<h2>Summary Information</h2>
<table class="info">
<tr><th>Status:</th><td>{% if summary.failed == 0 %}<span class="pass">All tests passed</span>{% else %}<span class="fail">{{ summary.failed }} test{{ 's' if summary.failed != 1 }} failed</span>{% endif %}</td></tr>
<tr><th>Procedure:</th><td><code>{{ script }}</code></td></tr>
<tr><th>Start Time:</th><td>{{ started }}</td></tr>
<tr><th>End Time:</th><td>{{ finished }}</td></tr>
<tr><th>Elapsed Time:</th><td>{{ elapsed }}</td></tr>
<tr><th>Telemetry Backend:</th><td>{{ backend }}</td></tr>
<tr><th>Conclusion:</th><td>{{ conclusion }}</td></tr>
{% if aborted %}<tr><th>Aborted:</th><td class="fail">{{ aborted }}</td></tr>{% endif %}
<tr><th>Input corpus:</th><td>{{ corpus_size }} coverage-increasing input trace(s) retained</td></tr>
<tr><th>Configuration:</th><td>{% for k, v in config.items() if k != 'script_path' %}<code>{{ k }}={{ v }}</code>{{ ', ' if not loop.last }}{% endfor %}</td></tr>
</table>
</section>

<section>
<h2>Test Statistics</h2>
<table>
<tr><th>Total Statistics</th><th class="num">Total</th><th class="num">Pass</th><th class="num">Fail</th><th class="num">Pass %</th><th class="num">Elapsed</th><th style="width:35%">Pass / Fail</th></tr>
<tr><td>All Fuzz Iterations</td><td class="num">{{ summary.total }}</td><td class="num pass">{{ summary.passed }}</td><td class="num fail">{{ summary.failed }}</td>
<td class="num">{{ summary.pass_pct }}%</td><td class="num">{{ elapsed }}</td>
<td><div class="graph" title="{{ summary.passed }} passed, {{ summary.failed }} failed"><b class="p" style="width:{{ summary.pass_pct }}%"></b><b class="f" style="width:{{ 100 - summary.pass_pct }}%"></b></div></td></tr>
<tr><th>Statistics by Strategy</th><th></th><th></th><th></th><th></th><th></th><th></th></tr>
{% for s in by_strategy %}
<tr><td>{{ s.name }}</td><td class="num">{{ s.total }}</td><td class="num pass">{{ s.passed }}</td><td class="num fail">{{ s.failed }}</td>
<td class="num">{{ s.pct }}%</td><td class="num">{{ s.elapsed }}</td>
<td><div class="graph"><b class="p" style="width:{{ s.pct }}%"></b><b class="f" style="width:{{ 100 - s.pct }}%"></b></div></td></tr>
{% endfor %}
</table>
</section>

<section>
<h2>Coverage Dashboard</h2>
<div class="cards">
 <div class="card"><div class="s">Line coverage</div><div class="v">{{ coverage.line_pct }}%</div><div class="s">{{ coverage.covered_lines }} / {{ coverage.statements }} statements</div><div class="meter"><i style="width:{{ coverage.line_pct }}%"></i></div></div>
 <div class="card"><div class="s">Branch coverage</div><div class="v">{{ coverage.branch_pct }}%</div><div class="s">{{ coverage.covered_branches }} / {{ coverage.branches }} branches</div><div class="meter"><i style="width:{{ coverage.branch_pct }}%;background:#2a7ae2"></i></div></div>
 <div class="card"><div class="s">Staleness interruptions</div><div class="v {{ 'fail' if stale_interruptions else '' }}">{{ stale_interruptions }}</div><div class="s">STALE_EXECUTION_TIMEOUT events</div></div>
 <div class="card"><div class="s">Early conclusion</div><div class="v">{{ 'YES' if concluded_early else 'NO' }}</div><div class="s">{{ progression|length }} iterations executed</div></div>
</div>
{% if progression %}
<h3 style="font-size:1em;margin:16px 0 4px">Coverage progression</h3>
<svg viewBox="0 0 {{ chart.w }} {{ chart.h }}" width="100%" height="{{ chart.h }}" preserveAspectRatio="none" role="img" aria-label="Coverage progression chart">
 <polygon class="area" points="{{ chart.area }}"/>
 <polyline class="l1" points="{{ chart.line }}"/>
 <polyline class="l2" points="{{ chart.branch }}"/>
 {% for x in chart.stale_x %}<line x1="{{ x }}" x2="{{ x }}" y1="0" y2="{{ chart.h }}" stroke="#ce3e01" stroke-dasharray="2 2"/>{% endfor %}
</svg>
<div class="legend"><span style="color:#5a8f29">━ line %</span><span style="color:#2a7ae2">┅ branch %</span><span style="color:#ce3e01">┆ staleness trigger</span></div>
{% endif %}

{% if events %}
<h3 style="font-size:1em;margin:16px 0 4px">Staleness &amp; timeout events</h3>
<table><tr><th>Timestamp</th><th>Event</th><th class="num">Iteration</th><th>Strategy</th><th>Detail</th><th>Action</th></tr>
{% for e in events %}<tr><td>{{ e.timestamp }}</td><td><span class="label evt">{{ e.event }}</span></td><td class="num">{{ e.iteration }}</td><td>{{ e.strategy }}</td><td>{{ e.detail }}</td><td>{{ e.action }}</td></tr>{% endfor %}
</table>
{% endif %}

<div class="element" style="margin-top:14px">
 <div class="element-header" onclick="tog(this)"><span class="tog">+</span><span class="label kw">SOURCE</span><span class="name">Annotated procedure source</span>
 <span class="el">missing lines: {{ coverage.missing_lines|join(', ') or 'none' }}</span></div>
 <div class="children"><table class="src">{% for l in source_lines %}<tr class="{{ l.cls }}"><td class="ln">{{ l.no }}</td><td class="code">{{ l.text }}</td></tr>{% endfor %}</table></div>
</div>
</section>

<section>
<h2>Test Execution Log</h2>
<div class="toolbar"><button id="expand-all" onclick="all_(true)">Expand all</button> <button id="collapse-all" onclick="all_(false)">Collapse all</button> <button id="expand-failed" onclick="failed()">Expand failed</button></div>
<div class="element open">
 <div class="element-header" onclick="tog(this)"><span class="tog">−</span><span class="label {{ 'pass' if summary.failed == 0 else 'fail' }}">{{ 'PASS' if summary.failed == 0 else 'FAIL' }}</span><span class="label test">SUITE</span><span class="name">{{ script_name }}</span><span class="el">{{ elapsed }}</span></div>
 <div class="children">
 {% for t in tests %}
 <div class="element test {{ t.status }}" id="test-{{ t.iteration }}">
  <div class="element-header" onclick="tog(this)"><span class="tog">+</span><span class="label {{ t.status }}">{{ t.status }}</span><span class="label test">TEST</span>
   <span class="name">{{ t.name }}</span>
   <span class="el">strategy={{ t.strategy }} · {{ t.origin }} · steps={{ t.steps|length }} · +{{ t.coverage.new_lines }} lines / +{{ t.coverage.new_arcs }} arcs · line {{ t.coverage.line_pct }}% · branch {{ t.coverage.branch_pct }}% · {{ t.elapsed_fmt }}</span></div>
  <div class="children">
   <table class="info"><tr><th>Start / End</th><td>{{ t.start }} → {{ t.end }}</td></tr>
   <tr><th>Inputs</th><td>{{ t.origin }} · {{ t.decisions }} decisions, {{ t.reused }} replayed from corpus</td></tr>
   {% if t.event %}<tr><th>Event</th><td><span class="label evt">{{ t.event }}</span></td></tr>{% endif %}
   {% if t.message %}<tr><th>Message</th><td class="fail">{{ t.message }}</td></tr>{% endif %}
   <tr><th>Coverage after run</th><td>{{ t.coverage.total_lines }} lines, {{ t.coverage.total_arcs }} arcs cumulative; stale counter {{ t.coverage.stale_count }}</td></tr></table>
   {% if t.traceback %}<pre>{{ t.traceback }}</pre>{% endif %}
   <table class="steps" style="margin-top:6px">
   <tr><th>Timestamp</th><th>Status</th><th>Keyword</th><th>Arguments</th><th>Injected value / Response</th><th class="num">Line</th><th class="num">Paths</th><th>Detail</th></tr>
   {% for s in t.steps %}<tr class="{{ s.status }}"><td>{{ s.timestamp[11:23] }}</td><td><span class="label {{ s.status }}">{{ s.status }}</span></td><td>{{ s.keyword }}</td><td>{{ s.args }}</td><td>{{ s.result }}</td>
   <td class="num">{{ s.line }}</td><td class="num">{% if s.new_path %}<span class="newpath" title="new execution transition">★{{ s.sites }}</span>{% else %}{{ s.sites }}{% endif %}</td><td>{{ s.detail }}</td></tr>
   {% else %}<tr><td colspan="8"><em>No API calls recorded</em></td></tr>{% endfor %}
   </table>
  </div>
 </div>
 {% endfor %}
 </div>
</div>
</section>
</main>
</div>
<script>
function tog(h){var e=h.parentNode,o=e.classList.toggle('open');h.querySelector('.tog').textContent=o?'−':'+';}
function set(e,o){e.classList.toggle('open',o);var t=e.querySelector(':scope>.element-header>.tog');if(t)t.textContent=o?'−':'+';}
function all_(o){document.querySelectorAll('.element').forEach(function(e){set(e,o)});}
function failed(){all_(false);document.querySelectorAll('.element').forEach(function(e,i){if(i===0)set(e,true)});
 document.querySelectorAll('.element.test.FAIL').forEach(function(e){set(e,true)});}
</script>
</body>
</html>
"""


def _chart(progression, events, w: int = 1000, h: int = 140) -> Dict[str, Any]:
    n = len(progression)
    if not n:
        return {}
    xs = [(i * w / (n - 1)) if n > 1 else w / 2 for i in range(n)]
    y = lambda pct: round(h - 4 - (h - 8) * float(pct) / 100.0, 1)  # noqa: E731
    line = " ".join(f"{x:.1f},{y(p.get('line_pct', 0))}" for x, p in zip(xs, progression))
    branch = " ".join(f"{x:.1f},{y(p.get('branch_pct', 0))}" for x, p in zip(xs, progression))
    stale_x = [round(xs[e["iteration"] - 1], 1) for e in events if 0 < e["iteration"] <= n]
    return {"w": w, "h": h, "line": line, "branch": branch, "stale_x": stale_x,
            "area": f"{xs[0]:.1f},{h} {line} {xs[-1]:.1f},{h}"}


def render_report(result: Dict[str, Any]) -> str:
    env = Environment(autoescape=select_autoescape(default=True, default_for_string=True))
    cov = result["coverage"]
    executed, missing = set(cov.get("executed_lines", [])), set(cov.get("missing_lines", []))
    partial = {int(a) for a, _ in cov.get("missing_branches", [])} if cov.get("missing_branches") else set()
    source_lines = []
    for no, text in enumerate(result.get("source", "").splitlines(), 1):
        cls = "par" if no in partial and no in executed else "run" if no in executed else "mis" if no in missing else ""
        source_lines.append({"no": no, "text": text, "cls": cls})

    strategies: Dict[str, Dict[str, Any]] = {}
    for t in result["tests"]:
        t["elapsed_fmt"] = _fmt_elapsed(t["elapsed"])
        s = strategies.setdefault(t["strategy"], {"name": t["strategy"], "total": 0, "passed": 0, "failed": 0, "secs": 0.0})
        s["total"] += 1
        s["passed" if t["status"] == "PASS" else "failed"] += 1
        s["secs"] += t["elapsed"]
    for s in strategies.values():
        s["pct"] = round(100.0 * s["passed"] / s["total"], 1)
        s["elapsed"] = _fmt_elapsed(s["secs"])

    return env.from_string(TEMPLATE).render(
        script=result["script"], script_name=os.path.basename(result["script"]),
        generated=datetime.now().strftime("%Y%m%d %H:%M:%S"),
        started=result["started"], finished=result["finished"], elapsed=_fmt_elapsed(result["elapsed"]),
        backend=result.get("backend", ""), conclusion=result.get("conclusion", ""), config=result.get("config", {}),
        aborted=result.get("aborted"), corpus_size=result.get("corpus_size", 0),
        summary=result["summary"], coverage=cov, progression=result["progression"], events=result["events"],
        stale_interruptions=result["stale_interruptions"], concluded_early=result["concluded_early"],
        chart=_chart(result["progression"], result["events"]), tests=result["tests"],
        by_strategy=list(strategies.values()), source_lines=source_lines)


def write_report(result: Dict[str, Any], output_path: str) -> str:
    html = render_report(result)
    out = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(html)
    return out


def write_junit(result: Dict[str, Any], output_path: str) -> str:
    """JUnit XML (one <testcase> per fuzz iteration) for CI test dashboards."""
    name = os.path.basename(result["script"])
    s = result["summary"]
    suites = ET.Element("testsuites", name="openc3-cosmos-script-fuzzer", tests=str(s["total"]),
                        failures=str(s["failed"]), errors="1" if result.get("aborted") else "0",
                        time=f"{result['elapsed']:.3f}")
    suite = ET.SubElement(suites, "testsuite", name=name, tests=str(s["total"]), failures=str(s["failed"]),
                          errors="1" if result.get("aborted") else "0", skipped="0",
                          time=f"{result['elapsed']:.3f}", timestamp=result["started"])
    props = ET.SubElement(suite, "properties")
    for k, v in (("line_pct", result["coverage"]["line_pct"]), ("branch_pct", result["coverage"]["branch_pct"]),
                 ("stale_interruptions", result["stale_interruptions"]), ("conclusion", result["conclusion"])):
        ET.SubElement(props, "property", name=k, value=str(v))
    for t in result["tests"]:
        case = ET.SubElement(suite, "testcase", classname=name.rsplit(".", 1)[0], name=t["name"],
                             time=f"{t['elapsed']:.3f}")
        if t["status"] == "FAIL":
            tag = "error" if t.get("event") == "INFRASTRUCTURE_ERROR" else "failure"
            el = ET.SubElement(case, tag, message=t["message"][:500], type=t.get("event") or "ProcedureFailure")
            el.text = t.get("traceback") or t["message"]
        out_lines = [f"strategy={t['strategy']} origin={t.get('origin', 'fresh')}"]
        out_lines += [f"{st['timestamp']} {st['status']:4} {st['keyword']} {st['args']} -> {st['result']}"
                      for st in t["steps"]]
        ET.SubElement(case, "system-out").text = "\n".join(out_lines)
    out = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    ET.indent(suites)
    ET.ElementTree(suites).write(out, encoding="utf-8", xml_declaration=True)
    return out
