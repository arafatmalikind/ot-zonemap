import argparse
import sys
from pathlib import Path

from . import __version__, checks, render
from .model import ModelError, load


def _write(content, dest):
    if dest:
        Path(dest).write_text(content, encoding="utf-8")
    else:
        sys.stdout.write(content)


def main(argv=None):
    p = argparse.ArgumentParser(prog="zonemap", description="Check and draw IEC 62443 zone/conduit models.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("check", help="run rule checks")
    c.add_argument("model")
    c.add_argument("--format", choices=["text", "json", "md"], default="text")
    c.add_argument("--skip", action="append", default=[], choices=list(checks.RULES))
    c.add_argument("--fail-on", choices=["high", "medium", "low", "never"], default="high",
                   help="exit 1 if a finding at or above this severity exists")
    c.add_argument("-o", "--output")

    d = sub.add_parser("diagram", help="emit a Mermaid diagram")
    d.add_argument("model")
    d.add_argument("-o", "--output")

    args = p.parse_args(argv)

    try:
        model = load(args.model)
    except (ModelError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.cmd == "diagram":
        _write(render.mermaid(model, checks.run(model)), args.output)
        return 0

    findings = checks.run(model, skip=set(args.skip))
    fmt = {"text": render.text, "json": lambda f: render.as_json(model, f),
           "md": lambda f: render.markdown(model, f)}[args.format]
    _write(fmt(findings), args.output)

    if args.fail_on == "never":
        return 0
    limit = checks.SEVERITY_ORDER[args.fail_on]
    return 1 if any(checks.SEVERITY_ORDER[f.severity] <= limit for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
