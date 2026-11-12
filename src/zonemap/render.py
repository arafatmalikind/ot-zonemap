import json
from collections import Counter

LEVEL_LABELS = {
    5: "L5 Enterprise",
    4: "L4 Business",
    3.5: "L3.5 Industrial DMZ",
    3: "L3 Operations",
    2: "L2 Supervisory",
    1: "L1 Control",
    0: "L0 Process",
}


def _nid(s):
    return "".join(ch if ch.isalnum() else "_" for ch in s)


def mermaid(model, findings=()):
    flagged = {f.subject for f in findings if f.severity == "high"}
    lines = ["flowchart TB"]

    for level in sorted(LEVEL_LABELS, reverse=True):
        zones = [z for z in model.zones.values() if z.level == level]
        if not zones:
            continue
        lines.append(f'  subgraph {_nid("L" + str(level))}["{LEVEL_LABELS[level]}"]')
        for z in zones:
            lines.append(f'    {_nid(z.id)}["{z.name}<br/>SL-T {z.sl_t}"]')
        lines.append("  end")

    for i, c in enumerate(model.conduits):
        arrow = "<-->" if c.bidirectional else "-->"
        label = ", ".join(c.protocols) or c.id
        lines.append(f'  {_nid(c.src)} {arrow}|"{label}"| {_nid(c.dst)}')
        if c.id in flagged:
            lines.append(f"  linkStyle {i} stroke:#d64545,stroke-width:3px")

    for z in model.zones.values():
        if z.id in flagged:
            lines.append(f"  style {_nid(z.id)} stroke:#d64545,stroke-width:3px")

    return "\n".join(lines) + "\n"


def markdown(model, findings):
    counts = Counter(f.severity for f in findings)
    out = [
        f"# Zone and conduit review: {model.name}",
        "",
        f"{len(model.zones)} zones, {len(model.conduits)} conduits. "
        f"Findings: {counts['high']} high, {counts['medium']} medium, {counts['low']} low.",
        "",
        "## Zones",
        "",
        "| Zone | Level | SL-T | SL-A (FR1-FR7) |",
        "|---|---|---|---|",
    ]
    for z in sorted(model.zones.values(), key=lambda z: -z.level):
        vec = " ".join(str(z.sl_a.get(f"FR{i}", "-")) for i in range(1, 8)) if z.sl_a else "not assessed"
        out.append(f"| {z.name} | {z.level:g} | {z.sl_t} | {vec} |")

    out += ["", "## Findings", ""]
    if not findings:
        out.append("No findings.")
    else:
        out += ["| Severity | Rule | Where | Detail |", "|---|---|---|---|"]
        for f in findings:
            out.append(f"| {f.severity} | {f.rule} | {f.subject} | {f.message} |")

    out += ["", "## Diagram", "", "```mermaid", mermaid(model, findings).rstrip(), "```", ""]
    return "\n".join(out)


def as_json(model, findings):
    return json.dumps(
        {
            "model": model.name,
            "zones": len(model.zones),
            "conduits": len(model.conduits),
            "findings": [f.as_dict() for f in findings],
        },
        indent=2,
    )


def text(findings):
    if not findings:
        return "no findings\n"
    w = max(len(f.subject) for f in findings)
    r = max(len(f.rule) for f in findings)
    return "".join(
        f"{f.severity.upper():<7}{f.subject:<{w + 2}}{f.rule:<{r + 2}}{f.message}\n" for f in findings
    )
