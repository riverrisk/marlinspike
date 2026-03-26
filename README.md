# MarlinSpike

MarlinSpike is a ground-up passive OT/ICS network analysis platform built in the tradition of GrassMarlin-style topology mapping, but wrapped in a multi-user web workbench designed for real engagements. It analyzes PCAP and PCAPNG captures, builds a topology graph, infers Purdue levels, fingerprints vendors, and surfaces responder-grade risk indicators such as cross-zone communication, cleartext services, beaconing, suspicious external communications, and DNS exfiltration, then exports everything as portable JSON report artifacts that travel with the team.

![MarlinSpike Hero](docs/screenshots/00-hero.png)

**Designed for on-site team engagements** — multi-user, zero-JS core workflows, `1 core / 1 GB RAM`, and portable JSON report artifacts.

**1.1M packets -> 46 nodes, 1,344 edges, 432 findings in 29 seconds.**

Repository: [github.com/riverrisk/marlinspike](https://github.com/riverrisk/marlinspike)

## What MarlinSpike Is

MarlinSpike is not just a topology viewer and it is not just a packet parser.

It is a field-deployable analyst platform built around four ideas:

- Passive OT/ICS analysis first: capture files in, no packets sent back onto the network.
- Ground-up GrassMarlin-style replacement: modern topology reconstruction, protocol-aware classification, and analyst-friendly reporting without inheriting the old single-user desktop model.
- Multi-user workbench: projects, uploads, reports, history, administration, and a shared URL the whole engagement team can use at once.
- Portable report contract: the engine can run headlessly, produce report artifacts, and those artifacts can be reviewed in the built-in workbench or consumed elsewhere.

The result is a different operating model than a desktop analyzer. MarlinSpike is meant to be dropped onto a temporary engagement host, fed captures from taps, SPAN ports, or external collection, and used collaboratively during triage and assessment.

## Design Principles

MarlinSpike is built around a few practical constraints:

- The engine remains standalone and can produce report artifacts headlessly.
- The report artifact is the handoff between packet analysis and downstream review.
- The primary workflow is `project -> scan -> report -> workbench -> triage actions`.
- Core web workflows remain usable without client-side JavaScript.

Interactive browser features can improve speed and convenience, but the core triage experience should still be accessible directly from rendered HTML.

## Highlights

- Passive analysis only: no active scanning or packet transmission
- OT protocol parsing for Modbus, EtherNet/IP, S7, DNP3, PROFINET, OPC UA, BACnet, and more
- Topology construction with Purdue-level inference and vendor fingerprinting
- Risk surfacing for remote access exposure, C2-like beaconing, suspicious external channels, DNS entropy anomalies, policy violations, selected MITRE ATT&CK mappings, and IEC 62443 SR-oriented remediation guidance
- Flask web UI with project management, report viewer, diff viewer, asset inventory, scan history, and optional local live capture mode
- Docker Compose deployment with PostgreSQL backing the application
- Optional Rust DPI stage via [`marlinspike-dpi`](https://github.com/riverrisk/marlinspike-dpi), with Python analysis and report shaping retained above it

## Quick Start

1. Clone the repository and enter the project directory.

```bash
git clone https://github.com/riverrisk/marlinspike.git
cd marlinspike
```

2. Copy the example environment file and set strong secrets.

```bash
cp .env.example .env
```

3. Build and start the stack.

```bash
docker compose up -d --build
```

4. Open the app at `http://127.0.0.1:5001` or through your reverse proxy.

On first boot, MarlinSpike creates an admin user. If `ADMIN_PASSWORD` is empty, a random password is generated and printed to the container logs.

See [INSTALL.md](INSTALL.md) for a generic deployment walkthrough.

## Positioning: Analyst Workbench vs Desktop Tool

MarlinSpike is not a general-purpose desktop analyzer. It is purpose-built as a temporary on-site analyst workbench for OT security engagements and assessments.

| Aspect | MarlinSpike (this project) | Typical desktop GRASSMARLIN-style tools |
|------|------|------|
| **Primary Use Case** | Spin up on an IPC or field laptop during a plant-floor engagement, review team-collected PCAPs, and hand back portable assessment artifacts | Solo deep-dive analysis on a single workstation |
| **User Model** | Multi-user, project-scoped workflow with auth, admin controls, and audit history | Usually single-user first |
| **Deployment** | Lightweight Docker Compose web app with zero-JS core workflows and a `1 core / 1 GB RAM` target | Desktop GUI application with heavier client-side runtime expectations |
| **Report Workflow** | PCAP from anywhere to self-contained JSON report artifacts, viewable here or consumable elsewhere, plus PDF/PNG/CSV exports | Tool-centric workflow with tighter coupling to the local application |
| **Operational Model** | Shared URL for the engagement team, fast setup and teardown, suitable for temporary or air-gapped field use | Persistent analyst desktop environment |
| **Extensibility** | Python analysis pipeline and HTML templates that are approachable for most security teams | Often centered on compiled desktop stacks with a steeper customization path |

In short:
Drop MarlinSpike on an air-gapped or temporary engagement host, hand the URL to the team, feed it the captures you collected, export clean portable JSON reports, and tear it down when the job is done.

If you are looking for a permanent single-user desktop application with a different feature focus, MarlinSpike is not trying to be that tool, and that is intentional.

## Feature Parity with GrassMarlin

MarlinSpike is meant to replace the core passive-mapping workflow people historically used GrassMarlin for, while changing the wrapper around it from a single-user desktop app to a shared web workbench.

| Capability | MarlinSpike status | Notes |
|------|------|------|
| Passive PCAP analysis | Yes | Accepts `pcap` and `pcapng` from the web UI or the standalone engine |
| OT-aware topology mapping | Yes | Relationship map, node/edge graph, vendor hints, and Purdue inference |
| Asset inventory | Yes | Per-asset roles, services, protocols, and responder-facing context |
| Protocol-aware OT analysis | Yes | Modbus, EtherNet/IP, S7, DNP3, PROFINET, OPC UA, BACnet, IEC 104, LLDP/CDP/STP/LACP, and more |
| Risk surfacing from passive traffic | Yes | Cleartext engineering, write-capable paths, suspicious external communications, beaconing, DNS exfiltration, and Purdue violations |
| Local live capture | Yes, optional | Exposed as an optional deployment feature rather than the main product contract |
| Exportable outputs | Yes | Portable JSON report artifacts, plus PDF/PNG/CSV export paths from the UI |
| Team analyst workflow | Exceeds | Project-scoped collaboration, shared URL access, history, diffing, and admin controls are first-class instead of bolted on |
| Headless analysis contract | Exceeds | The engine can run independently, emit portable report artifacts, and be reviewed later in the workbench or elsewhere |
| Thick desktop client | Different by design | Replaced with a browser-based workbench and zero-JS core workflows for temporary, shared field deployment |

### Improving Actively

- Fingerprint depth and classification confidence across more vendors and device families
- Server-rendered analyst drill-down flows in the viewer
- Richer use of Bronze-level protocol observations and extracted artifacts in the report UI
- Broader protocol-native enrichment beyond the current report contract

### Honest Boundaries

- MarlinSpike is not an active scanner.
- MarlinSpike is not a permanent desktop thick client.
- The standalone Rust DPI engine is a dissection substrate, not the whole product.
- Some protocol coverage and higher-level scoring still live in the Python analysis layer today, by design.

## Engine Architecture

MarlinSpike keeps packet dissection separate from analyst workflow.

### Current Analysis Stack

- Stage 1: capture ingestion and validation
- Stage 2: protocol dissection
- Stage 3: topology construction, Purdue inference, and fingerprinting
- Stage 4: breach-triage and risk surfacing
- Output: portable JSON report artifact consumed by the web workbench

### DPI Engine Options

MarlinSpike can currently run Stage 2 in two ways:

- Built-in Python/tshark-based dissection via `_ms_engine.py`
- External Rust dissection via [`marlinspike-dpi`](https://github.com/riverrisk/marlinspike-dpi)

The Rust path is intentionally scoped as a standalone DPI engine. MarlinSpike can call it as an external Stage 2 parser, adapt its Bronze output back into the current report pipeline, and continue using the existing topology, triage, and reporting layers. That keeps the packet parser reusable without forcing the analyst product to collapse into the parser.

### What `marlinspike-dpi` Means Today

- It is a standalone Rust DPI engine with CLI, library, and FFI surfaces.
- It accepts classic `pcap` and `pcapng` capture input.
- It emits structured Bronze events that MarlinSpike can consume.
- It replaces the dissection stage, not the higher-level breach-triage logic.

That is deliberate. MarlinSpike's value is not just decoding packets quickly. Its value is turning passive OT traffic into topology, findings, and responder decisions a team can actually use.

## Detection and Standards Coverage

MarlinSpike's current public detection and standards story is intentionally bounded to what the engine already emits today.

- Selected MITRE ATT&CK mappings are already present for C2 and exfiltration-oriented findings, including `T1071`, `T1573`, `T1048`, `T1132`, and `T1029`
- Purdue Model inference and cross-level communication checks are part of the core triage workflow
- Stage 4 remediation guidance is aligned to IEC 62443 SR requirements for the finding classes currently produced by the engine

This is not yet positioned as a full ATT&CK-for-ICS rule library or a full compliance control crosswalk. The current value is targeted, responder-facing mapping tied to the findings MarlinSpike can defend from passive traffic.

## Feature Overview

MarlinSpike turns raw packet captures into a workflow an OT operator, asset owner, or responder can actually use.

### Analysis

- Passive PCAP and PCAPNG analysis with OT-aware protocol dissection
- Relationship map and topology reconstruction with Purdue inference
- Report-driven triage with risk findings, C2 indicators, and asset context
- Detailed asset inventory, service exposure, conversation analysis, and MAC table reporting

### Workflow

- Ad hoc scan execution from the web UI
- Multi-capture handling, including large-PCAP processing with streaming progress
- Project-scoped organization for captures and reports
- Report history, retry support, and report-to-report diff viewing
- Portable JSON report artifacts that can be reviewed inside MarlinSpike or elsewhere

### Administration

- Multi-user access with admin controls
- Scan history and audit trail
- System health and monitoring views
- Sample library management and optional local live-capture mode

## Export Support

The report workflow supports export directly from the UI:

- Print or save to PDF from the report viewer
- PNG export from the topology viewer
- CSV export from the asset inventory view

## Additional Capabilities

- Report-to-report diffing with added, removed, changed, and unchanged topology comparison
- Live topology viewing during active scans
- Scan-stage progress streaming with ingest, analyze, classify, and report state visibility
- Per-user administration controls including password resets and upload limits
- Multi-report lifecycle actions including view, download, delete, and compare
- Retry of failed or interrupted scans from scan history
- Sample library administration with category management and PCAP upload/delete controls
- Capture filter input and ephemeral-port suppression controls in the scan workflow
- MAC table reporting alongside the main assessment view

## Screenshots

Click any thumbnail for the full-size image.

<table>
  <tr>
    <td width="50%">
      <a href="docs/screenshots/01-topology-viewer.png">
        <img src="docs/screenshots/01-topology-viewer.png" alt="Topology viewer" width="100%">
      </a>
      <br>
      <sub>Topology viewer and analyst workbench</sub>
    </td>
    <td width="50%">
      <a href="docs/screenshots/02-report-viewer.png">
        <img src="docs/screenshots/02-report-viewer.png" alt="Assessment findings and report view" width="100%">
      </a>
      <br>
      <sub>Assessment findings and report review</sub>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <a href="docs/screenshots/03-asset-inventory.png">
        <img src="docs/screenshots/03-asset-inventory.png" alt="Asset inventory" width="100%">
      </a>
      <br>
      <sub>Asset inventory and device context</sub>
    </td>
    <td width="50%">
      <a href="docs/screenshots/06-large-pcap-streaming.png">
        <img src="docs/screenshots/06-large-pcap-streaming.png" alt="Large PCAP progress" width="100%">
      </a>
      <br>
      <sub>Large-PCAP execution with live progress</sub>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <a href="docs/screenshots/07-scan-history.png">
        <img src="docs/screenshots/07-scan-history.png" alt="Scan history" width="100%">
      </a>
      <br>
      <sub>Scan history and audit trail</sub>
    </td>
    <td width="50%">
      <a href="docs/screenshots/08-projects.png">
        <img src="docs/screenshots/08-projects.png" alt="Projects workspace" width="100%">
      </a>
      <br>
      <sub>Project-scoped workflow</sub>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <a href="docs/screenshots/09-users.png">
        <img src="docs/screenshots/09-users.png" alt="User administration" width="100%">
      </a>
      <br>
      <sub>Multi-user administration</sub>
    </td>
    <td width="50%">
      <a href="docs/screenshots/11-diff-viewer.png">
        <img src="docs/screenshots/11-diff-viewer.png" alt="Diff viewer" width="100%">
      </a>
      <br>
      <sub>Report-to-report diffing</sub>
    </td>
  </tr>
</table>

## Configuration

The main environment variables are:

- `DB_PASSWORD`: PostgreSQL password
- `SECRET_KEY`: Flask session secret
- `ADMIN_PASSWORD`: initial admin password
- `ENABLE_LIVE_CAPTURE`: set to `true` to expose local interface capture in the UI
- `PCAP_MAX_SIZE`: maximum accepted upload size in bytes
- `PCAP_PROCESS_SIZE`: processing cap for auto-sliced uploads in bytes

## Source Layout

The canonical application modules are:

- `_ms_engine.py`
- `_auth.py`
- `_models.py`
- `_config.py`
- `app.py`

The non-underscored modules (`auth.py`, `models.py`, `config.py`) are compatibility shims so older tooling can still import them without drifting from the real source.

## Sample Data

The public repository does not bundle third-party PCAP corpora. If you want a preset sample library, add captures under `presets/<category>/` locally or through the admin UI after deployment.

## Development

- `python3 -m py_compile app.py _auth.py _config.py _models.py _ms_engine.py`
- `docker compose up --build`

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines, including ongoing fingerprinting and enrichment work.

## Fathom

MarlinSpike is the open-source core of **Fathom**, the commercial OT security platform from [River Risk Partners](https://riverriskpartners.com).

The commercial Fathom platform adds distributed collectors, hierarchy, data diodes, forensic time-travel, and enterprise-scale baseline learning. MarlinSpike is the lightweight, open-core workbench you can spin up anywhere.

Learn more at [riverriskpartners.com](https://riverriskpartners.com).

## License

This repository is licensed under the GNU Affero General Public License v3.0. See [LICENSE](LICENSE).
