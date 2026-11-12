from dataclasses import dataclass, field
from pathlib import Path

import yaml

FRS = ("FR1", "FR2", "FR3", "FR4", "FR5", "FR6", "FR7")

# Purdue levels we accept. 3.5 is the industrial DMZ.
LEVELS = (0, 1, 2, 3, 3.5, 4, 5)

BOUNDARY_CONTROLS = {"firewall", "diode", "unidirectional_gateway"}


class ModelError(ValueError):
    pass


@dataclass
class Zone:
    id: str
    name: str
    level: float
    sl_t: int
    sl_a: dict = field(default_factory=dict)
    assets: list = field(default_factory=list)
    remote_access: bool = False


@dataclass
class Conduit:
    id: str
    src: str
    dst: str
    protocols: list = field(default_factory=list)
    controls: set = field(default_factory=set)
    bidirectional: bool = True
    remote_access: bool = False


@dataclass
class Model:
    name: str
    zones: dict
    conduits: list

    def zone(self, zid):
        return self.zones[zid]


def _sl_vector(raw, zid):
    if raw is None:
        return {}
    if isinstance(raw, int):
        return {fr: raw for fr in FRS}
    if not isinstance(raw, dict):
        raise ModelError(f"zone {zid}: sl_a must be an int or a map of FR1..FR7")
    out = {}
    for k, v in raw.items():
        k = str(k).upper()
        if k not in FRS:
            raise ModelError(f"zone {zid}: unknown requirement {k}")
        if v not in (0, 1, 2, 3, 4):
            raise ModelError(f"zone {zid}: {k} must be 0-4, got {v}")
        out[k] = v
    return out


def parse(data):
    if not isinstance(data, dict) or "zones" not in data:
        raise ModelError("model needs a top level 'zones' list")

    zones = {}
    for z in data["zones"]:
        zid = z.get("id")
        if not zid:
            raise ModelError("every zone needs an id")
        if zid in zones:
            raise ModelError(f"duplicate zone id {zid}")
        level = z.get("level")
        if level not in LEVELS:
            raise ModelError(f"zone {zid}: level must be one of {LEVELS}")
        sl_t = z.get("sl_t", 1)
        if sl_t not in (1, 2, 3, 4):
            raise ModelError(f"zone {zid}: sl_t must be 1-4")
        zones[zid] = Zone(
            id=zid,
            name=z.get("name", zid),
            level=level,
            sl_t=sl_t,
            sl_a=_sl_vector(z.get("sl_a"), zid),
            assets=list(z.get("assets", [])),
            remote_access=bool(z.get("remote_access", False)),
        )

    conduits = []
    seen = set()
    for c in data.get("conduits", []):
        cid = c.get("id")
        if not cid:
            raise ModelError("every conduit needs an id")
        if cid in seen:
            raise ModelError(f"duplicate conduit id {cid}")
        seen.add(cid)
        src, dst = c.get("from"), c.get("to")
        for end in (src, dst):
            if end not in zones:
                raise ModelError(f"conduit {cid}: unknown zone {end}")
        if src == dst:
            raise ModelError(f"conduit {cid}: from and to are the same zone")
        conduits.append(
            Conduit(
                id=cid,
                src=src,
                dst=dst,
                protocols=[p.lower() for p in c.get("protocols", [])],
                controls={x.lower() for x in c.get("controls", [])},
                bidirectional=c.get("direction", "both") == "both",
                remote_access=bool(c.get("remote_access", False)),
            )
        )

    return Model(name=data.get("name", "unnamed"), zones=zones, conduits=conduits)


def load(path):
    with Path(path).open(encoding="utf-8") as fh:
        return parse(yaml.safe_load(fh))
