"""Helpers for loading vendored MITRE ATT&CK metadata."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

DEFAULT_ATTACK_CATALOG_PATH = Path(__file__).resolve().parent / "catalog" / "attack_catalog.json"
DEFAULT_DOMAIN = "enterprise-attack"
DOMAIN_ALIASES = {
    "enterprise": "enterprise-attack",
    "enterprise-attack": "enterprise-attack",
    "ics": "ics-attack",
    "ics-attack": "ics-attack",
}


def normalize_domain(value: str | None) -> str:
    return DOMAIN_ALIASES.get(str(value or "").strip().lower(), DEFAULT_DOMAIN)


@lru_cache(maxsize=1)
def load_attack_catalog(path: str | Path = DEFAULT_ATTACK_CATALOG_PATH) -> dict[str, Any]:
    catalog_path = Path(path)
    with catalog_path.open() as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"ATT&CK catalog must be a mapping: {catalog_path}")
    domains = payload.get("domains")
    if not isinstance(domains, dict):
        raise ValueError(f"ATT&CK catalog missing domains: {catalog_path}")
    return payload


def get_domain_catalog(domain: str | None, catalog: dict[str, Any] | None = None) -> dict[str, Any]:
    loaded = catalog or load_attack_catalog()
    canonical = normalize_domain(domain)
    domain_catalog = dict((loaded.get("domains") or {}).get(canonical) or {})
    if not domain_catalog:
        raise KeyError(f"ATT&CK domain not found in catalog: {canonical}")
    return domain_catalog


def get_domain_metadata(domain: str | None, catalog: dict[str, Any] | None = None) -> dict[str, Any]:
    domain_catalog = get_domain_catalog(domain, catalog)
    return {
        "domain": domain_catalog.get("domain"),
        "name": domain_catalog.get("name"),
        "attack_version": domain_catalog.get("attack_version"),
        "bundle_modified": domain_catalog.get("bundle_modified"),
        "source_url": domain_catalog.get("source_url"),
        "matrix": dict(domain_catalog.get("matrix") or {}),
    }


def get_technique_metadata(technique_id: str, domain: str | None, catalog: dict[str, Any] | None = None) -> dict[str, Any]:
    domain_catalog = get_domain_catalog(domain, catalog)
    techniques = dict(domain_catalog.get("techniques") or {})
    return dict(techniques.get(str(technique_id or "").strip().upper()) or {})
