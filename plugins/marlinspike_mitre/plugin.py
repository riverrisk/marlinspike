"""marlinspike-mitre ATT&CK mapping plugin.

Consumes a finished MarlinSpike report JSON and emits a sidecar JSON artifact
containing ATT&CK classifications, platform coverage, matrix-ready tactic data,
versioned ATT&CK metadata, and response guidance.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from . import CONTRACT_VERSION, PLUGIN_ID, PLUGIN_VERSION
from .attack_catalog import (
    DEFAULT_ATTACK_CATALOG_PATH,
    DEFAULT_DOMAIN,
    get_domain_catalog,
    get_domain_metadata,
    get_technique_metadata,
    load_attack_catalog,
    normalize_domain,
)

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[2] / "rules" / "mitre" / "base.yaml"
BASIS_RANK = {"observed": 0, "inferred": 1, "platform": 2}
GUIDANCE_PRIORITY = {"critical": 0, "high": 1, "medium": 2, "informational": 3}


def _listify(value: Any) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _slug(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "-", str(value or "").strip().lower()).strip("-") or "unknown"


def _clean_text(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _short_text(value: Any, limit: int = 320) -> str:
    text = _clean_text(value)
    if len(text) <= limit:
        return text
    return text[: limit - 3].rstrip() + "..."


def _append_unique(target: list[str], values: list[str]) -> None:
    existing = set(target)
    for value in values:
        if value and value not in existing:
            target.append(value)
            existing.add(value)


def _merge_dict_list(items: list[dict], key_name: str = "id") -> list[dict]:
    merged: dict[str, dict] = {}
    ordered: list[str] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        key = str(item.get(key_name) or item.get("name") or item.get("url") or "").strip()
        if not key:
            continue
        if key not in merged:
            merged[key] = dict(item)
            ordered.append(key)
    return [merged[key] for key in ordered]


def _load_json(path: Path) -> dict:
    with path.open() as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"Report must be a JSON object: {path}")
    return payload


def _validate_conditions(when: dict, path: str = "when") -> None:
    for key in ("all_of", "any_of"):
        if key not in when:
            continue
        clauses = when.get(key)
        if not isinstance(clauses, list):
            raise ValueError(f"{path}.{key} must be a list")
        for index, clause in enumerate(clauses):
            if not isinstance(clause, dict):
                raise ValueError(f"{path}.{key}[{index}] must be a mapping")
            _validate_conditions(clause, f"{path}.{key}[{index}]")


def _load_rule_pack(path: Path, catalog: dict) -> dict:
    with path.open() as handle:
        payload = yaml.safe_load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"Rule pack must be a mapping: {path}")
    if int(payload.get("schema_version") or 0) != 1:
        raise ValueError(f"Unsupported MITRE rule schema_version in {path}")
    if payload.get("plugin_id") != PLUGIN_ID:
        raise ValueError(f"Rule pack plugin_id mismatch in {path}")

    rules = payload.get("rules")
    if not isinstance(rules, list):
        raise ValueError(f"Rule pack rules must be a list: {path}")

    default_domain = normalize_domain(payload.get("default_domain"))
    if default_domain not in (catalog.get("domains") or {}):
        raise ValueError(f"Unsupported default_domain in {path}: {default_domain}")

    normalized_rules: list[dict] = []
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise ValueError(f"Rule at index {index} in {path} must be a mapping")
        technique_id = str(rule.get("technique_id") or "").strip().upper()
        if not technique_id:
            raise ValueError(f"Rule missing technique_id in {path}: {rule.get('id') or index}")
        kind = str(rule.get("kind") or "classification").strip()
        if kind not in {"classification", "coverage"}:
            raise ValueError(f"Unsupported rule kind in {path}: {kind}")
        response_guidance = _listify(rule.get("response_guidance"))
        if any(not str(step).strip() for step in response_guidance):
            raise ValueError(f"response_guidance contains empty values in {path}: {rule.get('id') or index}")

        when = dict(rule.get("when") or {})
        _validate_conditions(when)

        domain = normalize_domain(rule.get("domain") or default_domain)
        if domain not in (catalog.get("domains") or {}):
            raise ValueError(f"Unsupported ATT&CK domain in {path}: {domain}")

        normalized_rule = dict(rule)
        normalized_rule["technique_id"] = technique_id
        normalized_rule["kind"] = kind
        normalized_rule["domain"] = domain
        normalized_rule["response_guidance"] = [str(step).strip() for step in response_guidance if str(step).strip()]
        normalized_rule["when"] = when
        normalized_rules.append(normalized_rule)

    payload["default_domain"] = default_domain
    payload["rules"] = normalized_rules
    return payload


def _build_observation_index(items: list[dict], key_name: str, prefix: str) -> tuple[Counter, dict[str, list[dict]]]:
    counts: Counter = Counter()
    matches: dict[str, list[dict]] = defaultdict(list)
    for item in items:
        if not isinstance(item, dict):
            continue
        label = str(item.get(key_name) or "").strip().upper()
        if not label:
            continue
        counts[label] += 1
        ref = f"{prefix}:{_slug(label)}:{counts[label]}"
        matches[label].append({"ref": ref, "item": item})
    return counts, matches


def _build_context(report: dict) -> dict:
    nodes = list(report.get("nodes") or [])
    edges = list(report.get("edges") or [])
    findings = list(report.get("risk_findings") or [])
    indicators = list(report.get("c2_indicators") or [])
    protocol_summary = dict(report.get("protocol_summary") or {})

    finding_counts, finding_matches = _build_observation_index(findings, "category", "finding")
    indicator_counts, indicator_matches = _build_observation_index(indicators, "type", "indicator")

    return {
        "report": report,
        "nodes": nodes,
        "edges": edges,
        "findings": findings,
        "indicators": indicators,
        "protocol_summary": protocol_summary,
        "finding_counts": finding_counts,
        "finding_matches": finding_matches,
        "indicator_counts": indicator_counts,
        "indicator_matches": indicator_matches,
        "node_count": len(nodes),
        "edge_count": len(edges),
        "has_capture": isinstance(report.get("capture_info"), dict),
        "has_nodes": bool(nodes),
        "has_edges": bool(edges),
        "has_protocols": bool(protocol_summary),
    }


def _primitive_matches(when: dict, ctx: dict) -> bool:
    for field in ("has_capture", "has_nodes", "has_edges", "has_protocols"):
        if field in when and bool(ctx[field]) != bool(when[field]):
            return False

    if int(when.get("min_nodes") or 0) > ctx["node_count"]:
        return False
    if int(when.get("min_edges") or 0) > ctx["edge_count"]:
        return False

    finding_categories = [str(value).upper() for value in _listify(when.get("finding_categories")) if str(value).strip()]
    if finding_categories and not any(ctx["finding_counts"].get(category, 0) for category in finding_categories):
        return False

    indicator_types = [str(value).upper() for value in _listify(when.get("indicator_types")) if str(value).strip()]
    if indicator_types and not any(ctx["indicator_counts"].get(indicator_type, 0) for indicator_type in indicator_types):
        return False

    return True


def _conditions_match(when: dict, ctx: dict) -> bool:
    primitive = {key: value for key, value in when.items() if key not in {"all_of", "any_of"}}
    if primitive and not _primitive_matches(primitive, ctx):
        return False

    all_of = [item for item in _listify(when.get("all_of")) if isinstance(item, dict)]
    if all_of and not all(_conditions_match(item, ctx) for item in all_of):
        return False

    any_of = [item for item in _listify(when.get("any_of")) if isinstance(item, dict)]
    if any_of and not any(_conditions_match(item, ctx) for item in any_of):
        return False

    return True


def _rule_matches(rule: dict, ctx: dict) -> bool:
    return _conditions_match(dict(rule.get("when") or {}), ctx)


def _extract_observation_filters(when: dict) -> tuple[set[str], set[str]]:
    finding_categories = {str(value).upper() for value in _listify(when.get("finding_categories")) if str(value).strip()}
    indicator_types = {str(value).upper() for value in _listify(when.get("indicator_types")) if str(value).strip()}
    for key in ("all_of", "any_of"):
        for clause in _listify(when.get(key)):
            if isinstance(clause, dict):
                child_findings, child_indicators = _extract_observation_filters(clause)
                finding_categories.update(child_findings)
                indicator_types.update(child_indicators)
    return finding_categories, indicator_types


def _collect_rule_evidence(rule: dict, ctx: dict) -> tuple[list[str], list[str], list[str]]:
    finding_categories, indicator_types = _extract_observation_filters(dict(rule.get("when") or {}))

    mapped_from: set[str] = set()
    evidence_refs: list[str] = []
    affected_nodes: set[str] = set()

    for category in finding_categories:
        for match in ctx["finding_matches"].get(category, []):
            mapped_from.add(category)
            evidence_refs.append(match["ref"])
            for node in _listify(match["item"].get("affected_nodes")):
                if node:
                    affected_nodes.add(str(node))

    for indicator_type in indicator_types:
        for match in ctx["indicator_matches"].get(indicator_type, []):
            mapped_from.add(indicator_type)
            evidence_refs.append(match["ref"])
            item = match["item"]
            for field in ("affected_nodes", "src", "dst"):
                value = item.get(field)
                if field == "affected_nodes":
                    for node in _listify(value):
                        if node:
                            affected_nodes.add(str(node))
                elif value:
                    affected_nodes.add(str(value))

    if not evidence_refs and rule.get("kind") == "coverage":
        evidence_refs.append(f"platform:{_slug(rule.get('technique_id') or rule.get('id'))}")

    return sorted(mapped_from), sorted(set(evidence_refs)), sorted(affected_nodes)


def _priority_for_item(item: dict) -> str:
    basis = str(item.get("basis") or "inferred")
    confidence = float(item.get("confidence") or 0.0)
    if basis == "platform":
        return "informational"
    if confidence >= 0.9:
        return "high"
    if confidence >= 0.75:
        return "medium"
    return "informational"


def _merge_guidance(target: dict, source: dict) -> dict:
    merged = dict(target)
    source_priority = str(source.get("priority") or "informational")
    target_priority = str(merged.get("priority") or "informational")
    if GUIDANCE_PRIORITY.get(source_priority, 99) < GUIDANCE_PRIORITY.get(target_priority, 99):
        merged["priority"] = source_priority
    merged["analyst_summary"] = str(merged.get("analyst_summary") or source.get("analyst_summary") or "")
    merged["detection_notes"] = str(merged.get("detection_notes") or source.get("detection_notes") or "")
    next_steps = list(_listify(merged.get("next_steps")))
    _append_unique(next_steps, [str(value).strip() for value in _listify(source.get("next_steps")) if str(value).strip()])
    merged["next_steps"] = next_steps
    references = list(_listify(merged.get("references")))
    _append_unique(references, [str(value).strip() for value in _listify(source.get("references")) if str(value).strip()])
    merged["references"] = references
    mitigation_focus = list(_listify(merged.get("mitigation_focus")))
    _append_unique(
        mitigation_focus,
        [str(value).strip() for value in _listify(source.get("mitigation_focus")) if str(value).strip()],
    )
    merged["mitigation_focus"] = mitigation_focus
    return merged


def _build_response_guidance(item: dict, rule: dict, technique: dict) -> dict:
    tactic_names = [str(tactic.get("name") or "").strip() for tactic in item.get("tactics") or [] if str(tactic.get("name") or "").strip()]
    affected_nodes = [str(node).strip() for node in _listify(item.get("affected_nodes")) if str(node).strip()]
    evidence_refs = [str(ref).strip() for ref in _listify(item.get("evidence_refs")) if str(ref).strip()]
    mitigation_names = [str(mitigation.get("name") or "").strip() for mitigation in item.get("mitigations") or [] if str(mitigation.get("name") or "").strip()]

    next_steps: list[str] = []
    _append_unique(next_steps, list(_listify(rule.get("response_guidance"))))

    if affected_nodes:
        target_preview = ", ".join(affected_nodes[:4])
        _append_unique(
            next_steps,
            [
                f"Pivot on the affected assets first: {target_preview}."
                + (" Validate whether the traffic pattern is expected for their role." if item.get("basis") != "platform" else "")
            ],
        )

    if evidence_refs:
        _append_unique(next_steps, [f"Trace the mapping back to the observed evidence refs: {', '.join(evidence_refs[:4])}."])

    if tactic_names:
        _append_unique(next_steps, [f"Frame triage around the ATT&CK tactic(s): {', '.join(tactic_names[:3])}."])

    if item.get("basis") == "platform":
        _append_unique(
            next_steps,
            [
                "Treat this as ATT&CK coverage context for passive analysis, not as a confirmed incident on its own.",
            ],
        )
    else:
        _append_unique(
            next_steps,
            [
                "Confirm whether the observed behavior is approved or expected before escalating containment.",
                "If the behavior is unexpected, preserve packet evidence and isolate the host or channel long enough to collect endpoint context.",
            ],
        )

    if mitigation_names:
        _append_unique(
            next_steps,
            [f"Review ATT&CK mitigations that best fit this behavior: {', '.join(mitigation_names[:3])}."],
        )

    references = [str(item.get("technique_url") or "").strip()]
    _append_unique(references, [str(tactic.get("url") or "").strip() for tactic in item.get("tactics") or []])

    analyst_summary = _short_text(
        rule.get("rationale")
        or technique.get("description")
        or f"{item.get('title') or item.get('technique_id')} mapped from passive network evidence."
    )

    return {
        "priority": _priority_for_item(item),
        "analyst_summary": analyst_summary,
        "next_steps": next_steps,
        "detection_notes": _short_text(technique.get("detection")),
        "mitigation_focus": mitigation_names[:5],
        "references": [ref for ref in references if ref],
    }


def _enrich_attack_item(item: dict, rule: dict, catalog: dict, warnings: list[str]) -> dict:
    domain = normalize_domain(rule.get("domain"))
    technique = get_technique_metadata(item["technique_id"], domain, catalog)
    domain_meta = get_domain_metadata(domain, catalog)

    enriched = dict(item)
    enriched["domain"] = domain
    enriched["attack_version"] = domain_meta.get("attack_version")
    enriched["technique_url"] = str(technique.get("url") or "")
    enriched["attack_name"] = str(technique.get("name") or item.get("title") or item["technique_id"])
    enriched["description"] = str(technique.get("description") or "")
    enriched["detection"] = str(technique.get("detection") or "")
    enriched["platforms"] = sorted(set(str(value).strip() for value in _listify(technique.get("platforms")) if str(value).strip()))
    enriched["tactics"] = list(technique.get("tactics") or [])
    enriched["tactic_ids"] = [str(tactic.get("id") or "").strip() for tactic in enriched["tactics"] if str(tactic.get("id") or "").strip()]
    enriched["tactic_shortnames"] = [str(tactic.get("shortname") or "").strip() for tactic in enriched["tactics"] if str(tactic.get("shortname") or "").strip()]
    enriched["is_subtechnique"] = bool(technique.get("is_subtechnique"))
    enriched["parent_technique_id"] = str(technique.get("parent_technique_id") or "")
    enriched["parent_technique_name"] = str(technique.get("parent_technique_name") or "")
    enriched["parent_technique_url"] = str(technique.get("parent_technique_url") or "")
    enriched["mitigations"] = list(technique.get("mitigations") or [])
    enriched["rule_ids"] = [str(rule.get("id") or "").strip()] if str(rule.get("id") or "").strip() else []
    enriched["response_guidance"] = _build_response_guidance(enriched, rule, technique)

    if not technique:
        warnings.append(f"ATT&CK technique metadata missing for {domain}:{item['technique_id']}")

    return enriched


def _merge_item(target: dict, source: dict) -> dict:
    merged = dict(target)
    if float(source.get("confidence") or 0.0) > float(merged.get("confidence") or 0.0):
        merged["confidence"] = float(source.get("confidence") or 0.0)
    if BASIS_RANK.get(str(source.get("basis") or "inferred"), 99) < BASIS_RANK.get(str(merged.get("basis") or "inferred"), 99):
        merged["basis"] = source.get("basis")

    for field in (
        "domain",
        "attack_version",
        "technique_url",
        "attack_name",
        "description",
        "detection",
        "parent_technique_id",
        "parent_technique_name",
        "parent_technique_url",
    ):
        if source.get(field) and not merged.get(field):
            merged[field] = source.get(field)

    merged["mapped_from"] = sorted(set(_listify(merged.get("mapped_from"))) | set(_listify(source.get("mapped_from"))))
    merged["evidence_refs"] = sorted(set(_listify(merged.get("evidence_refs"))) | set(_listify(source.get("evidence_refs"))))
    merged["affected_nodes"] = sorted(set(_listify(merged.get("affected_nodes"))) | set(_listify(source.get("affected_nodes"))))
    merged["platforms"] = sorted(set(_listify(merged.get("platforms"))) | set(_listify(source.get("platforms"))))
    merged["tactic_ids"] = sorted(set(_listify(merged.get("tactic_ids"))) | set(_listify(source.get("tactic_ids"))))
    merged["tactic_shortnames"] = sorted(set(_listify(merged.get("tactic_shortnames"))) | set(_listify(source.get("tactic_shortnames"))))
    merged["rule_ids"] = sorted(set(_listify(merged.get("rule_ids"))) | set(_listify(source.get("rule_ids"))))
    merged["mitigations"] = _merge_dict_list(list(_listify(merged.get("mitigations"))) + list(_listify(source.get("mitigations"))))
    merged["tactics"] = _merge_dict_list(list(_listify(merged.get("tactics"))) + list(_listify(source.get("tactics"))))
    merged["is_subtechnique"] = bool(merged.get("is_subtechnique") or source.get("is_subtechnique"))
    if source.get("rationale") and not merged.get("rationale"):
        merged["rationale"] = source.get("rationale")
    if source.get("response_guidance"):
        merged["response_guidance"] = (
            _merge_guidance(dict(merged.get("response_guidance") or {}), dict(source.get("response_guidance") or {}))
            if merged.get("response_guidance")
            else dict(source.get("response_guidance") or {})
        )
    return merged


def _build_matrix(classification_list: list[dict], coverage_list: list[dict], active_domains: list[str], catalog: dict) -> dict:
    by_domain: dict[str, list[tuple[str, dict]]] = defaultdict(list)
    for item in classification_list:
        by_domain[str(item.get("domain") or DEFAULT_DOMAIN)].append(("classification", item))
    for item in coverage_list:
        by_domain[str(item.get("domain") or DEFAULT_DOMAIN)].append(("coverage", item))

    domains_payload: list[dict] = []
    for domain in active_domains:
        domain_catalog = get_domain_catalog(domain, catalog)
        tactics = dict(domain_catalog.get("tactics") or {})
        tactic_order = list((domain_catalog.get("matrix") or {}).get("tactic_order") or tactics.keys())

        tactic_entries: list[dict] = []
        for tactic_id in tactic_order:
            tactic = dict(tactics.get(tactic_id) or {})
            hits: list[dict] = []
            for kind, item in by_domain.get(domain, []):
                if tactic_id not in set(item.get("tactic_ids") or []):
                    continue
                hits.append(
                    {
                        "technique_id": item.get("technique_id"),
                        "title": item.get("title"),
                        "attack_name": item.get("attack_name"),
                        "technique_url": item.get("technique_url"),
                        "kind": kind,
                        "status": "classified" if kind == "classification" else "covered",
                        "basis": item.get("basis"),
                        "confidence": item.get("confidence"),
                        "family": item.get("family"),
                        "is_subtechnique": item.get("is_subtechnique"),
                        "parent_technique_id": item.get("parent_technique_id"),
                        "parent_technique_name": item.get("parent_technique_name"),
                        "affected_nodes": item.get("affected_nodes"),
                    }
                )

            hits = sorted(
                hits,
                key=lambda value: (
                    0 if value.get("kind") == "classification" else 1,
                    BASIS_RANK.get(str(value.get("basis") or "inferred"), 99),
                    -float(value.get("confidence") or 0.0),
                    str(value.get("technique_id") or ""),
                ),
            )

            tactic_entries.append(
                {
                    "tactic_id": tactic.get("id"),
                    "name": tactic.get("name"),
                    "shortname": tactic.get("shortname"),
                    "url": tactic.get("url"),
                    "description": tactic.get("description"),
                    "technique_total": len(list(domain_catalog.get("tactic_techniques", {}).get(tactic_id) or [])),
                    "mapped_total": len(hits),
                    "classified_total": len([entry for entry in hits if entry.get("kind") == "classification"]),
                    "coverage_total": len([entry for entry in hits if entry.get("kind") == "coverage"]),
                    "entries": hits,
                }
            )

        domains_payload.append(
            {
                **get_domain_metadata(domain, catalog),
                "tactics": tactic_entries,
            }
        )

    return {
        "primary_domain": active_domains[0] if active_domains else DEFAULT_DOMAIN,
        "domains": domains_payload,
    }


def _build_attack_metadata(active_domains: list[str], catalog: dict) -> dict:
    return {
        "catalog_schema_version": catalog.get("catalog_schema_version"),
        "catalog_generated_at": catalog.get("generated_at"),
        "source_index_url": catalog.get("source_index_url"),
        "domains": {
            domain: get_domain_metadata(domain, catalog)
            for domain in active_domains
        },
    }


def _classify(report: dict, packs: list[dict], catalog: dict) -> dict:
    ctx = _build_context(report)
    classifications: dict[str, dict] = {}
    platform_coverage: dict[str, dict] = {}
    pack_ids: list[str] = []
    warnings: list[str] = []
    mapped_categories: set[str] = set()
    active_domains: set[str] = set()

    for pack in packs:
        pack_ids.append(str(pack.get("pack_id") or "unknown-pack"))
        active_domains.add(normalize_domain(pack.get("default_domain")))
        for rule in pack.get("rules") or []:
            if not isinstance(rule, dict) or not rule.get("enabled", True):
                continue
            if not _rule_matches(rule, ctx):
                continue

            mapped_from, evidence_refs, affected_nodes = _collect_rule_evidence(rule, ctx)
            technique_id = str(rule.get("technique_id") or "").strip().upper()
            if not technique_id:
                warnings.append(f"Rule missing technique_id: {rule.get('id') or 'unknown'}")
                continue

            item = {
                "technique_id": technique_id,
                "title": str(rule.get("title") or technique_id),
                "family": str(rule.get("family") or "Unknown"),
                "publication": str(rule.get("publication") or "Plugin mapping"),
                "basis": str(rule.get("basis") or ("platform" if rule.get("kind") == "coverage" else "observed")),
                "confidence": float(rule.get("confidence") or 0.0),
                "mapped_from": mapped_from,
                "affected_nodes": affected_nodes,
                "evidence_refs": evidence_refs,
                "rationale": str(rule.get("rationale") or ""),
            }
            item = _enrich_attack_item(item, rule, catalog, warnings)
            active_domains.add(str(item.get("domain") or DEFAULT_DOMAIN))

            storage_key = f"{item['domain']}::{technique_id}"
            if rule.get("kind") == "coverage":
                existing = platform_coverage.get(storage_key)
                platform_coverage[storage_key] = _merge_item(existing, item) if existing else item
            else:
                existing = classifications.get(storage_key)
                classifications[storage_key] = _merge_item(existing, item) if existing else item
                mapped_categories.update(mapped_from)

    unmapped_categories = sorted(
        category
        for category in ctx["finding_counts"].keys()
        if category not in mapped_categories
    )
    basis_counts = Counter(str(item.get("basis") or "inferred") for item in classifications.values())

    classification_list = sorted(
        classifications.values(),
        key=lambda item: (
            BASIS_RANK.get(str(item.get("basis") or "inferred"), 99),
            -float(item.get("confidence") or 0.0),
            str(item.get("domain") or ""),
            str(item.get("technique_id") or ""),
        ),
    )
    coverage_list = sorted(
        platform_coverage.values(),
        key=lambda item: (
            str(item.get("domain") or ""),
            str(item.get("family") or ""),
            str(item.get("technique_id") or ""),
        ),
    )

    active_domain_list = sorted(active_domains)
    matrix = _build_matrix(classification_list, coverage_list, active_domain_list, catalog)
    unique_tactics = {
        str(tactic.get("id") or "")
        for item in classification_list + coverage_list
        for tactic in item.get("tactics") or []
        if str(tactic.get("id") or "").strip()
    }
    subtechniques = {
        str(item.get("technique_id") or "")
        for item in classification_list + coverage_list
        if item.get("is_subtechnique")
    }

    return {
        "summary": {
            "classification_total": len(classification_list),
            "observed_total": int(basis_counts.get("observed", 0)),
            "inferred_total": int(basis_counts.get("inferred", 0)),
            "platform_coverage_total": len(coverage_list),
            "mapped_category_total": len(mapped_categories),
            "unmapped_category_total": len(unmapped_categories),
            "tactic_total": len(unique_tactics),
            "subtechnique_total": len(subtechniques),
            "matrix_domain_total": len(active_domain_list),
        },
        "data": {
            "classifications": classification_list,
            "platform_coverage": coverage_list,
            "coverage": {
                "mapped_categories": sorted(mapped_categories),
                "unmapped_categories": unmapped_categories,
            },
            "matrix": matrix,
            "pack_ids": sorted(set(pack_ids)),
            "supported_techniques": sorted(
                set(item["technique_id"] for item in classification_list)
                | set(item["technique_id"] for item in coverage_list)
            ),
        },
        "attack_metadata": _build_attack_metadata(active_domain_list, catalog),
        "warnings": sorted(set(warnings)),
    }


def run(input_report: Path, output_path: Path, rule_paths: list[Path], attack_catalog_path: Path = DEFAULT_ATTACK_CATALOG_PATH) -> dict:
    report = _load_json(input_report)
    catalog = load_attack_catalog(attack_catalog_path)
    packs = [_load_rule_pack(path, catalog) for path in rule_paths]
    result = _classify(report, packs, catalog)
    artifact = {
        "artifact_type": "plugin_output",
        "plugin_id": PLUGIN_ID,
        "plugin_version": PLUGIN_VERSION,
        "contract_version": CONTRACT_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_report": input_report.name,
        "summary": result["summary"],
        "data": result["data"],
        "attack_metadata": result["attack_metadata"],
        "warnings": result["warnings"],
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w") as handle:
        json.dump(artifact, handle, indent=2)
    return artifact


def main() -> None:
    parser = argparse.ArgumentParser(prog=PLUGIN_ID, description="Generate ATT&CK mappings for a MarlinSpike report")
    parser.add_argument("--input-report", required=True, help="Path to the finished MarlinSpike report JSON")
    parser.add_argument("--output", required=True, help="Path to the output sidecar JSON artifact")
    parser.add_argument("--rules", action="append", default=[], help="Additional YAML rule pack(s) to load")
    parser.add_argument(
        "--attack-catalog",
        default=str(DEFAULT_ATTACK_CATALOG_PATH),
        help="Path to the vendored ATT&CK catalog JSON",
    )
    args = parser.parse_args()

    input_report = Path(args.input_report).resolve()
    output_path = Path(args.output).resolve()
    rule_paths = [Path(path).resolve() for path in (args.rules or [])] or [DEFAULT_RULES_PATH]
    attack_catalog_path = Path(args.attack_catalog).resolve()

    artifact = run(input_report, output_path, rule_paths, attack_catalog_path)
    summary = artifact.get("summary") or {}
    print(
        f"[mitre] classifications={summary.get('classification_total', 0)} "
        f"platform_coverage={summary.get('platform_coverage_total', 0)} "
        f"tactics={summary.get('tactic_total', 0)} "
        f"unmapped_categories={summary.get('unmapped_category_total', 0)}"
    )
