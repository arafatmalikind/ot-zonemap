"""Rule checks against a zone/conduit model.

Each rule takes the model and yields Finding objects. Rules are kept small
and independent so they can be switched off from the CLI.
"""

from dataclasses import dataclass

from .model import BOUNDARY_CONTROLS, FRS

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

# Protocols with no authentication or integrity of their own.
CLEARTEXT_OT = {"modbus", "modbus/tcp", "dnp3", "s7comm", "ethernet/ip", "bacnet", "iec104", "opc-da"}
CLEARTEXT_IT = {"telnet", "ftp", "http", "snmpv1", "snmpv2c", "tftp", "vnc"}


@dataclass
class Finding:
    rule: str
    severity: str
    subject: str
    message: str

    def as_dict(self):
        return self.__dict__.copy()


def _ends(model, c):
    return model.zone(c.src), model.zone(c.dst)


def level_skip(model):
    """Enterprise (L4/L5) talking straight to control levels (L0-L2)."""
    for c in model.conduits:
        a, b = _ends(model, c)
        hi, lo = (a, b) if a.level > b.level else (b, a)
        if hi.level >= 4 and lo.level <= 2:
            yield Finding(
                "level-skip", "high", c.id,
                f"{hi.name} (L{hi.level:g}) reaches {lo.name} (L{lo.level:g}) without passing a DMZ",
            )
        elif hi.level >= 4 and lo.level == 3:
            yield Finding(
                "level-skip", "medium", c.id,
                f"{hi.name} connects directly to operations zone {lo.name}; route it through L3.5",
            )


def missing_boundary(model):
    """Conduits between zones with different SL-T need a real boundary device."""
    for c in model.conduits:
        a, b = _ends(model, c)
        if a.sl_t != b.sl_t and not (c.controls & BOUNDARY_CONTROLS):
            sev = "high" if abs(a.sl_t - b.sl_t) >= 2 else "medium"
            yield Finding(
                "missing-boundary", sev, c.id,
                f"SL-T changes {a.sl_t}->{b.sl_t} across this conduit but no firewall or diode is listed",
            )


def cleartext_upward(model):
    """Unauthenticated protocols leaving the control network."""
    for c in model.conduits:
        a, b = _ends(model, c)
        top = max(a.level, b.level)
        bad_ot = [p for p in c.protocols if p in CLEARTEXT_OT]
        bad_it = [p for p in c.protocols if p in CLEARTEXT_IT]
        if bad_ot and top >= 3.5:
            yield Finding(
                "cleartext-ot", "high", c.id,
                f"{', '.join(bad_ot)} carried up to L{top:g}; terminate it at L3 and replicate data instead",
            )
        if bad_it:
            yield Finding(
                "cleartext-it", "medium", c.id,
                f"cleartext management protocol(s): {', '.join(bad_it)}",
            )


def diode_direction(model):
    """A diode on a two-way conduit is either mislabelled or bypassed."""
    for c in model.conduits:
        if {"diode", "unidirectional_gateway"} & c.controls and c.bidirectional:
            yield Finding(
                "diode-direction", "medium", c.id,
                "conduit is marked as a diode but direction is 'both'",
            )


def remote_access(model):
    for c in model.conduits:
        if not c.remote_access:
            continue
        a, b = _ends(model, c)
        if "mfa" not in c.controls:
            yield Finding("remote-access-mfa", "high", c.id, "remote access path without MFA")
        if "jump_host" not in c.controls and min(a.level, b.level) <= 2:
            yield Finding(
                "remote-access-jump", "high", c.id,
                "remote access lands in a control zone without a jump host",
            )
        if "session_recording" not in c.controls:
            yield Finding("remote-access-recording", "low", c.id, "remote sessions are not recorded")


def sl_gap(model):
    """Compare declared SL-A per FR against the zone's SL-T."""
    for z in model.zones.values():
        if not z.sl_a:
            yield Finding("sl-unassessed", "low", z.id, f"{z.name} has no SL-A recorded")
            continue
        short = [(fr, z.sl_a[fr]) for fr in FRS if fr in z.sl_a and z.sl_a[fr] < z.sl_t]
        missing = [fr for fr in FRS if fr not in z.sl_a]
        if short:
            worst = max(z.sl_t - v for _, v in short)
            sev = "high" if worst >= 2 else "medium"
            detail = ", ".join(f"{fr}={v}" for fr, v in short)
            yield Finding("sl-gap", sev, z.id, f"{z.name} target SL{z.sl_t}, below target on {detail}")
        if missing:
            yield Finding("sl-partial", "low", z.id, f"{z.name} not assessed for {', '.join(missing)}")


def orphan_zones(model):
    used = {c.src for c in model.conduits} | {c.dst for c in model.conduits}
    for z in model.zones.values():
        if z.id not in used and len(model.zones) > 1:
            yield Finding(
                "orphan-zone", "low", z.id,
                f"{z.name} has no conduits; either it is isolated or a path is undocumented",
            )


RULES = {
    "level-skip": level_skip,
    "missing-boundary": missing_boundary,
    "cleartext": cleartext_upward,
    "diode-direction": diode_direction,
    "remote-access": remote_access,
    "sl-gap": sl_gap,
    "orphan-zone": orphan_zones,
}


def run(model, skip=()):
    out = []
    for name, rule in RULES.items():
        if name in skip:
            continue
        out.extend(rule(model))
    out.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.rule, f.subject))
    return out
