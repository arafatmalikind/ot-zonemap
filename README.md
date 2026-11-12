# ot-zonemap

Describe an OT network as IEC 62443 zones and conduits in a YAML file, run a set of design checks against it, and get a Mermaid diagram out the other end.

I wrote this because zone and conduit reviews usually live in Visio files and spreadsheets that drift away from reality within a month of the assessment. Keeping the model as YAML means it can sit in Git next to firewall rule exports, get reviewed in a pull request, and be re-checked automatically whenever someone adds a conduit.

It is a design review aid, not a scanner. It only knows what you put in the model.

## What it checks

| Rule | What it catches |
|---|---|
| `level-skip` | Enterprise zones (L4/L5) connected straight to L0-L2 or L3 without going through the industrial DMZ |
| `missing-boundary` | A conduit joins zones with different target security levels and has no firewall or diode on it |
| `cleartext` | Modbus, DNP3, S7, EtherNet/IP etc. carried up to L3.5 or above, and Telnet/FTP/VNC/SNMPv1-2c anywhere |
| `diode-direction` | A conduit marked as a data diode but modelled as two-way |
| `remote-access` | Remote access paths missing MFA, a jump host (when landing in L0-L2) or session recording |
| `sl-gap` | Achieved SL (per FR1-FR7) below the zone's target SL, plus zones that were never assessed |
| `orphan-zone` | Zones with no conduits, which usually means an undocumented path |

Severity is high, medium or low. The CLI exits non-zero when it finds anything at or above `--fail-on` (default `high`), so it can gate a pipeline.

## Install

```bash
git clone https://github.com/<your-user>/ot-zonemap.git
cd ot-zonemap
pip install -e ".[dev]"
```

## Usage

```bash
zonemap check examples/gas-plant.yaml
zonemap check examples/gas-plant.yaml --format md -o review.md --fail-on never
zonemap check model.yaml --format json --skip orphan-zone
zonemap diagram examples/gas-plant.yaml -o plant.mmd
```

Sample output against the bundled example:

```
HIGH   c08    cleartext-ot        modbus/tcp carried up to L4; terminate it at L3 and replicate data instead
HIGH   c08    level-skip          Site business network (L4) reaches Field controllers (L1) without passing a DMZ
HIGH   c08    remote-access-mfa   remote access path without MFA
HIGH   dcs    sl-gap              DCS supervisory target SL3, below target on FR1=2, FR2=2, FR4=1, FR6=2
MEDIUM c07    diode-direction     conduit is marked as a diode but direction is 'both'
...
```

The full Markdown report for the example is in [docs/sample-report.md](docs/sample-report.md). GitHub renders the Mermaid block in it directly.

## Model format

```yaml
name: My site

zones:
  - id: dcs
    name: DCS supervisory
    level: 2            # 0, 1, 2, 3, 3.5, 4 or 5
    sl_t: 3             # target security level 1-4
    sl_a:               # achieved SL, either one number or per FR
      FR1: 2
      FR2: 2
      FR3: 3
    assets: [operator-hmi, dcs-servers]

conduits:
  - id: c04
    from: ops
    to: dcs
    protocols: [opc-ua]
    controls: [firewall]          # firewall, diode, mfa, jump_host, session_recording ...
    direction: both               # or "one" for a diode
    remote_access: false
```

`sl_a` is optional. If it is missing the zone is reported as unassessed rather than silently passing.

## Design notes

- Purdue levels are used as a practical proxy for "how close to the process is this". IEC 62443 itself does not mandate the Purdue model, so treat level-based rules as opinionated defaults and skip them if your architecture differs.
- SL-A is taken as declared. Deriving it from the SR/RE requirements in 62443-3-3 would need a full control inventory per zone, which is out of scope for now.
- The diagram highlights anything with a high finding in red so it can go straight into a review deck.

## Roadmap

- Import conduits from a firewall rule export (Palo Alto and FortiGate first)
- Per-asset protocol whitelist to compare against passive monitoring data
- HTML report

## License

MIT. See [LICENSE](LICENSE).
