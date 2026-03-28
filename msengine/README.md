# marlinspike-msengine

This directory is the bootstrap subtree prefix for the future standalone
`marlinspike-msengine` component repo.

## Current Transition Rules

- The active suite runtime still executes the root `_ms_engine.py` file.
- The extracted package copy lives at `msengine/engine.py`.
- The OUI database copy lives at `msengine/data/oui.json`.
- The sync helper is [`../scripts/sync-msengine-bootstrap.sh`](../scripts/sync-msengine-bootstrap.sh).

That means the subtree copy is real and importable, but the operational
source-of-truth remains the root engine file until the standalone repo cutover is
complete.

## Package Layout

- `pyproject.toml`
  Packaging metadata for the standalone engine repo.
- `msengine/__main__.py`
  Enables `python -m msengine`.
- `msengine/engine.py`
  Bootstrapped copy of the current suite engine.
- `msengine/data/oui.json`
  Bootstrapped copy of the current OUI database.

## Stage 4b Malware Engine Integration

The Stage 4b malware engine integration (IOC/signature matching via
`marlinspike-malware`) remains part of core engine orchestration and is not
extracted to a plugin. When `msengine` extracts to its standalone repo, the
malware binary discovery and event conversion logic (`_run_malware_stage` and
helpers) travel with it.

## Local Usage

From the suite repo root:

```bash
PYTHONPATH=msengine python3 -m msengine --help
```

From the extracted component repo root later:

```bash
python3 -m msengine --help
```
