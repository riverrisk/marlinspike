#!/usr/bin/env python3
"""Validate that Bronze enrichments survive the MarlinSpike adapter."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def run_json_command(cmd: list[str], output_path: Path) -> dict:
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "").strip() or f"command failed: {' '.join(cmd)}")
    with output_path.open() as handle:
        return json.load(handle)


def summarize_bronze(payload: dict) -> dict:
    output = payload.get("output") or {}
    events = output.get("events") or []
    protocol_txs = []
    asset_obs = []
    for event in events:
        family = event.get("family") or {}
        if "protocol_transaction" in family:
            protocol_txs.append(family["protocol_transaction"] or {})
        elif "asset_observation" in family:
            asset_obs.append(family["asset_observation"] or {})

    first_tx = protocol_txs[0] if protocol_txs else {}
    return {
        "dpi_ok": True,
        "bronze_protocol_transactions": len(protocol_txs),
        "bronze_asset_observations": len(asset_obs),
        "bronze_first_operation": first_tx.get("operation", ""),
        "bronze_first_attribute_keys": sorted((first_tx.get("attributes") or {}).keys()),
        "bronze_first_object_refs": first_tx.get("object_refs") or [],
        "schema_version": ((output.get("checkpoint") or {}).get("schema_version") or ""),
    }


def summarize_report(payload: dict) -> dict:
    conversations = payload.get("conversations") or []
    all_attr_keys = set()
    all_ops = set()
    object_ref_count = 0
    asset_enriched = 0

    for conv in conversations:
        all_attr_keys.update((conv.get("protocol_attributes") or {}).keys())
        all_ops.update(conv.get("operations_seen") or [])
        object_ref_count += len(conv.get("protocol_object_refs") or [])
        if conv.get("src_asset") or conv.get("dst_asset"):
            asset_enriched += 1

    first_enriched = next(
        (
            conv
            for conv in conversations
            if conv.get("protocol_attributes") or conv.get("protocol_object_refs") or conv.get("src_asset") or conv.get("dst_asset")
        ),
        {},
    )

    return {
        "ms_ok": True,
        "report_protocol_summary": payload.get("protocol_summary") or {},
        "report_attribute_keys": sorted(all_attr_keys),
        "report_operations_seen": sorted(all_ops),
        "report_object_ref_count": object_ref_count,
        "report_asset_enriched_conversations": asset_enriched,
        "report_first_passthrough": {
            "protocol": first_enriched.get("protocol", ""),
            "operations_seen": first_enriched.get("operations_seen") or [],
            "protocol_attributes": first_enriched.get("protocol_attributes") or {},
            "protocol_object_refs": first_enriched.get("protocol_object_refs") or [],
            "src_asset": first_enriched.get("src_asset") or {},
            "dst_asset": first_enriched.get("dst_asset") or {},
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dpi-binary", required=True, help="Path to the marlinspike-dpi binary")
    parser.add_argument(
        "--engine-script",
        default=str(Path(__file__).resolve().parents[1] / "_ms_engine.py"),
        help="Path to the MarlinSpike engine script",
    )
    parser.add_argument(
        "--output-dir",
        default=str(Path(__file__).resolve().parents[1] / ".smoke" / "validation"),
        help="Directory for generated Bronze/report artifacts",
    )
    parser.add_argument("pcaps", nargs="+", help="PCAPs to validate")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    engine_script = Path(args.engine_script).resolve()
    dpi_binary = Path(args.dpi_binary).resolve()

    summary = {}
    for pcap_arg in args.pcaps:
        pcap = Path(pcap_arg).resolve()
        label = pcap.stem.lower().replace(" ", "-")
        bronze_path = output_dir / f"{label}-bronze.json"
        report_path = output_dir / f"{label}-report.json"
        item = {"pcap": str(pcap)}

        try:
            bronze_payload = run_json_command(
                [
                    str(dpi_binary),
                    "--input",
                    str(pcap),
                    "--capture-id",
                    f"validation-{label}",
                    "--output",
                    str(bronze_path),
                    "--pretty",
                ],
                bronze_path,
            )
            item.update(summarize_bronze(bronze_payload))
        except Exception as exc:  # noqa: BLE001
            item["dpi_ok"] = False
            item["dpi_error"] = str(exc)
            summary[label] = item
            continue

        try:
            report_payload = run_json_command(
                [
                    sys.executable,
                    str(engine_script),
                    "--dpi-engine",
                    "marlinspike-dpi",
                    "--dpi-binary",
                    str(dpi_binary),
                    "--pcap",
                    str(pcap),
                    "-o",
                    str(report_path),
                    "chain",
                ],
                report_path,
            )
            item.update(summarize_report(report_payload))
        except Exception as exc:  # noqa: BLE001
            item["ms_ok"] = False
            item["ms_error"] = str(exc)

        summary[label] = item

    summary_path = output_dir / "comparison-summary.json"
    with summary_path.open("w") as handle:
        json.dump(summary, handle, indent=2, sort_keys=True)

    print(f"[*] Validation summary written to {summary_path}")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
