from pathlib import Path

import pytest

from zonemap import checks, render
from zonemap.cli import main
from zonemap.model import ModelError, parse

EXAMPLE = Path(__file__).parent.parent / "examples" / "gas-plant.yaml"


def build(zones, conduits=()):
    return parse({"zones": zones, "conduits": list(conduits)})


def rules(model):
    return {(f.rule, f.subject, f.severity) for f in checks.run(model)}


def test_rejects_unknown_zone_in_conduit():
    with pytest.raises(ModelError, match="unknown zone"):
        build([{"id": "a", "level": 3}], [{"id": "x", "from": "a", "to": "b"}])


def test_rejects_bad_level():
    with pytest.raises(ModelError, match="level"):
        build([{"id": "a", "level": 6}])


def test_rejects_bad_fr_key():
    with pytest.raises(ModelError, match="unknown requirement"):
        build([{"id": "a", "level": 3, "sl_a": {"FR9": 2}}])


def test_level_skip_high():
    m = build(
        [{"id": "it", "level": 4, "sl_a": 2}, {"id": "plc", "level": 1, "sl_a": 2}],
        [{"id": "c", "from": "it", "to": "plc", "controls": ["firewall"]}],
    )
    assert ("level-skip", "c", "high") in rules(m)


def test_dmz_path_is_clean():
    m = build(
        [
            {"id": "it", "level": 4, "sl_t": 2, "sl_a": 2},
            {"id": "dmz", "level": 3.5, "sl_t": 2, "sl_a": 2},
            {"id": "ops", "level": 3, "sl_t": 2, "sl_a": 2},
        ],
        [
            {"id": "a", "from": "it", "to": "dmz", "protocols": ["https"], "controls": ["firewall"]},
            {"id": "b", "from": "dmz", "to": "ops", "protocols": ["https"], "controls": ["firewall"]},
        ],
    )
    assert checks.run(m) == []


def test_boundary_needed_when_sl_changes():
    m = build(
        [{"id": "a", "level": 3, "sl_t": 1, "sl_a": 1}, {"id": "b", "level": 2, "sl_t": 3, "sl_a": 3}],
        [{"id": "c", "from": "a", "to": "b"}],
    )
    assert ("missing-boundary", "c", "high") in rules(m)


def test_modbus_above_l3():
    m = build(
        [{"id": "dmz", "level": 3.5, "sl_a": 1}, {"id": "ops", "level": 3, "sl_a": 1}],
        [{"id": "c", "from": "dmz", "to": "ops", "protocols": ["Modbus/TCP"], "controls": ["firewall"]}],
    )
    assert ("cleartext-ot", "c", "high") in rules(m)


def test_two_way_diode():
    m = build(
        [{"id": "a", "level": 3, "sl_a": 1}, {"id": "b", "level": 3.5, "sl_a": 1}],
        [{"id": "c", "from": "a", "to": "b", "controls": ["diode"]}],
    )
    assert ("diode-direction", "c", "medium") in rules(m)
    m2 = build(
        [{"id": "a", "level": 3, "sl_a": 1}, {"id": "b", "level": 3.5, "sl_a": 1}],
        [{"id": "c", "from": "a", "to": "b", "controls": ["diode"], "direction": "one"}],
    )
    assert not any(f.rule == "diode-direction" for f in checks.run(m2))


def test_remote_access_rules():
    m = build(
        [{"id": "v", "level": 4, "sl_a": 1}, {"id": "f", "level": 1, "sl_a": 1}],
        [{"id": "c", "from": "v", "to": "f", "remote_access": True, "controls": ["firewall"]}],
    )
    got = rules(m)
    assert ("remote-access-mfa", "c", "high") in got
    assert ("remote-access-jump", "c", "high") in got


def test_sl_gap_severity():
    m = build([{"id": "z", "level": 2, "sl_t": 3, "sl_a": {"FR1": 1, "FR2": 3}}])
    got = rules(m)
    assert ("sl-gap", "z", "high") in got
    assert ("sl-partial", "z", "low") in got


def test_skip_rule():
    m = build([{"id": "z", "level": 2}])
    assert checks.run(m, skip={"sl-gap"}) == []


def test_example_model_findings():
    from zonemap.model import load

    m = load(EXAMPLE)
    found = checks.run(m)
    high = {(f.rule, f.subject) for f in found if f.severity == "high"}
    assert ("level-skip", "c08") in high
    assert ("remote-access-mfa", "c08") in high
    assert ("missing-boundary", "c05") not in high  # same SL-T both sides
    assert found[0].severity == "high"


def test_mermaid_has_all_zones():
    from zonemap.model import load

    m = load(EXAMPLE)
    out = render.mermaid(m)
    assert out.startswith("flowchart TB")
    for zid in m.zones:
        assert f"{zid}[" in out


def test_cli_exit_codes(tmp_path, capsys):
    assert main(["check", str(EXAMPLE)]) == 1
    assert main(["check", str(EXAMPLE), "--fail-on", "never"]) == 0
    bad = tmp_path / "bad.yaml"
    bad.write_text("zones: [{id: a, level: 9}]")
    assert main(["check", str(bad)]) == 2


def test_markdown_report(tmp_path):
    out = tmp_path / "r.md"
    main(["check", str(EXAMPLE), "--format", "md", "-o", str(out), "--fail-on", "never"])
    text = out.read_text()
    assert "## Findings" in text and "```mermaid" in text
