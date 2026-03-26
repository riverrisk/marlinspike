"""MarlinSpike — Standalone passive OT network topology mapper.

Flask web application with PostgreSQL-backed auth and scan history.
"""

import glob
import hashlib
import json
import logging
import os
import platform
import re
import secrets
import shutil
import subprocess
import threading
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import _config as config
from _auth import (
    admin_required,
    bootstrap_admin,
    change_password,
    create_user,
    login_required,
    verify_user,
)
from _models import Project, ScanHistory, User, db

APP_VERSION = "1.9.0"

log = logging.getLogger("marlinspike")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")

# PCAP magic bytes for validation
PCAP_MAGIC = {
    b"\xd4\xc3\xb2\xa1",  # pcap LE
    b"\xa1\xb2\xc3\xd4",  # pcap BE
    b"\x0a\x0d\x0d\x0a",  # pcapng
}


# ═══════════════════════════════════════════════════════════════
# Run registry — in-memory subprocess tracking
# ═══════════════════════════════════════════════════════════════

_run_registry = {}  # run_id -> {process, output, status, ...}
_runs_lock = threading.Lock()


def _cleanup_runs():
    """Remove completed/failed runs older than RUN_CLEANUP_SECONDS."""
    now = datetime.now(timezone.utc)
    to_remove = []
    for run_id, run in _run_registry.items():
        if run["status"] in ("completed", "failed", "stopped") and run.get("finished_at"):
            try:
                finished = datetime.fromisoformat(run["finished_at"])
                if (now - finished).total_seconds() > config.RUN_CLEANUP_SECONDS:
                    to_remove.append(run_id)
            except (ValueError, TypeError):
                pass
    for run_id in to_remove:
        del _run_registry[run_id]


MAX_CONCURRENT_SCANS = 1


def _get_active_runs():
    """Return list of (run_id, run_state) for all active runs."""
    active = []
    for run_id, run in _run_registry.items():
        if run["status"] in ("pending", "running"):
            active.append((run_id, run))
    return active


def _scan_artifacts(run_state):
    """Scan reports dir for artifact files produced by this run."""
    command = run_state["command"]
    reports_dir = os.path.dirname(run_state.get("report_path", "")) or config.REPORTS_DIR
    pattern = os.path.join(reports_dir, f"marlinspike-{command}-*.json")
    try:
        started = datetime.fromisoformat(run_state["started_at"]).timestamp()
    except (ValueError, TypeError):
        started = 0
    for path in glob.glob(pattern):
        try:
            if os.path.getmtime(path) >= started:
                with open(path) as f:
                    artifact = json.load(f)
                art_type = artifact.get("artifact_type", command)
                run_state["artifacts_produced"][art_type] = path
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════
# Submission archival helpers
# ═══════════════════════════════════════════════════════════════

def _archive_submission(src_path, user_id, username, original_filename):
    """Archive uploaded PCAP to submissions dir (background, TOS compliance)."""
    try:
        os.makedirs(os.path.join(config.SUBMISSIONS_DIR, str(user_id)), exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_fn = re.sub(r'[^a-zA-Z0-9._-]', '_', original_filename)[:120]
        base_name = f"{username}_{ts}_{safe_fn}"

        try:
            import zstandard as zstd
            dest = os.path.join(config.SUBMISSIONS_DIR, str(user_id), base_name + ".zst")
            cctx = zstd.ZstdCompressor(level=3)
            with open(src_path, "rb") as fin, open(dest, "wb") as fout:
                cctx.copy_stream(fin, fout)
        except ImportError:
            import gzip as gz
            dest = os.path.join(config.SUBMISSIONS_DIR, str(user_id), base_name + ".gz")
            with open(src_path, "rb") as fin, gz.open(dest, "wb", compresslevel=6) as fout:
                shutil.copyfileobj(fin, fout)
        log.info("Archived submission: %s (%s)", dest, original_filename)
    except Exception as e:
        log.warning("Failed to archive submission: %s", e)


# ═══════════════════════════════════════════════════════════════
# Flask app factory
# ═══════════════════════════════════════════════════════════════


def _sanitize_report(report: dict) -> dict:
    """Strip internal details from report before sending to browser."""
    r = report.copy()
    r.pop("tshark_version", None)
    if "capture_info" in r and isinstance(r["capture_info"], dict):
        ci = r["capture_info"] = r["capture_info"].copy()
        if "pcap_path" in ci:
            # Keep only filename, not full path
            ci["pcap_path"] = os.path.basename(ci["pcap_path"])
        ci.pop("tshark_path", None)
    return r


def _viewer_anchor(value: str) -> str:
    value = str(value or "").strip()
    return re.sub(r"[^a-zA-Z0-9_-]+", "-", value).strip("-") or "asset"


def _severity_rank(severity: str) -> int:
    return {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4,
    }.get((severity or "").upper(), 5)


def _build_viewer_context(report: dict) -> dict:
    """Prepare server-rendered triage context for the viewer."""
    nodes = list(report.get("nodes") or [])
    edges = list(report.get("edges") or [])
    risk_findings = list(report.get("risk_findings") or [])
    c2_indicators = sorted(
        list(report.get("c2_indicators") or []),
        key=lambda item: (_severity_rank(item.get("severity")), item.get("type", ""), item.get("src", "")),
    )
    protocol_summary = dict(report.get("protocol_summary") or {})
    port_summary = dict(report.get("port_summary") or {})
    purdue_violations = list(report.get("purdue_violations") or [])
    mac_table = list(report.get("mac_table") or [])

    node_risks = defaultdict(list)
    for finding in risk_findings:
        if finding.get("category") == "NO_AUTH_OBSERVED":
            continue
        for ip in finding.get("affected_nodes") or []:
            node_risks[str(ip)].append(finding)
    for items in node_risks.values():
        items.sort(key=lambda item: (_severity_rank(item.get("severity")), item.get("category", "")))

    def classify_score(node: dict) -> int:
        score = 0
        if node.get("vendor") and node.get("vendor") != "Unknown":
            score += 1
        if node.get("device_type") and node.get("device_type") != "Unknown":
            score += 1
        if node.get("product_line"):
            score += 1
        if node.get("system_name") or node.get("system_desc"):
            score += 1
        return score

    def node_priority_key(node: dict):
        ip = str(node.get("ip") or node.get("address") or "")
        risk_count = len(node_risks.get(ip, []))
        service_count = len(node.get("service_ports") or [])
        protocol_count = len(node.get("protocols") or [])
        return (
            int(node.get("attack_priority") or 0),
            risk_count,
            service_count,
            protocol_count,
            ip,
        )

    assets_sorted = []
    write_nodes = set()
    for edge in edges:
        if edge.get("includes_writes") or edge.get("includes_program_access"):
            if edge.get("src"):
                write_nodes.add(str(edge["src"]))
            if edge.get("dst"):
                write_nodes.add(str(edge["dst"]))

    for node in sorted(nodes, key=node_priority_key, reverse=True):
        ip = str(node.get("ip") or node.get("address") or "")
        related_risks = node_risks.get(ip, [])
        assets_sorted.append({
            **node,
            "_ip": ip,
            "_anchor": _viewer_anchor(ip),
            "_risk_count": len(related_risks),
            "_top_risk": related_risks[0] if related_risks else None,
            "_risk_findings": related_risks,
            "_classification_score": classify_score(node),
            "_has_writes": ip in write_nodes,
        })

    priority_nodes = [node for node in assets_sorted if int(node.get("attack_priority") or 0) > 0][:8]
    auth_gap_nodes = [node for node in assets_sorted if not node.get("auth_observed", False)][:8]
    unclassified_nodes = [node for node in assets_sorted if node["_classification_score"] == 0][:8]
    write_paths = [
        {
            **edge,
            "_anchor_src": _viewer_anchor(edge.get("src", "")),
            "_anchor_dst": _viewer_anchor(edge.get("dst", "")),
        }
        for edge in edges
        if edge.get("includes_writes") or edge.get("includes_program_access")
    ]
    write_paths.sort(key=lambda edge: (int(bool(edge.get("includes_program_access"))), int(bool(edge.get("includes_writes"))), int(edge.get("conversation_count") or 0)), reverse=True)

    external_types = {
        "C2_BEACONING",
        "C2_DNS_EXFIL",
        "C2_DNS_TUNNEL_SUSPECT",
        "C2_DNS_HIGH_ENTROPY",
        "C2_SUSPECT_CHANNEL",
        "C2_DATA_EXFIL",
        "C2_PERSISTENCE",
    }
    external_indicators = [item for item in c2_indicators if item.get("type") in external_types][:8]
    top_findings = sorted(
        risk_findings,
        key=lambda item: (_severity_rank(item.get("severity")), item.get("category", ""), item.get("description", "")),
    )[:8]

    protocol_items = [
        {"name": name, "count": count}
        for name, count in sorted(protocol_summary.items(), key=lambda item: (-int(item[1]), item[0]))
    ]
    port_items = [
        {"label": label, **details}
        for label, details in sorted(
            port_summary.items(),
            key=lambda item: (-int((item[1] or {}).get("connections") or 0), item[0]),
        )
    ]

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for finding in risk_findings:
        sev = str(finding.get("severity") or "").upper()
        if sev in severity_counts:
            severity_counts[sev] += 1

    summary = {
        "asset_count": len(nodes),
        "edge_count": len(edges),
        "protocol_count": len(protocol_items),
        "classified_count": sum(1 for node in assets_sorted if node["_classification_score"] > 0),
        "auth_gap_count": sum(1 for node in assets_sorted if not node.get("auth_observed", False)),
        "write_node_count": len(write_nodes),
        "write_edge_count": len(write_paths),
        "priority_count": len([node for node in assets_sorted if int(node.get("attack_priority") or 0) > 0]),
        "external_count": len([node for node in assets_sorted if node.get("purdue_level") == 5 or node.get("role") == "External Host"]),
        "critical_high_count": severity_counts["CRITICAL"] + severity_counts["HIGH"],
        "severity_counts": severity_counts,
        "packet_count": (report.get("capture_info") or {}).get("total_packets"),
        "duration_seconds": (report.get("capture_info") or {}).get("duration_seconds"),
    }
    summary["unclassified_count"] = max(0, summary["asset_count"] - summary["classified_count"])

    return {
        "summary": summary,
        "assets_sorted": assets_sorted,
        "priority_nodes": priority_nodes,
        "auth_gap_nodes": auth_gap_nodes,
        "unclassified_nodes": unclassified_nodes,
        "write_paths": write_paths[:10],
        "top_findings": top_findings,
        "external_indicators": external_indicators,
        "protocol_items": protocol_items[:10],
        "port_items": port_items[:12],
        "purdue_violations": purdue_violations,
        "c2_indicators": c2_indicators,
        "mac_table": mac_table,
    }


def create_app():
    app = Flask(__name__)

    # Config
    secret = config.SECRET_KEY
    if not secret:
        secret = secrets.token_hex(32)
        print(f"[marlinspike] Generated SECRET_KEY (set SECRET_KEY env var to persist)")
    app.secret_key = secret
    app.config["SQLALCHEMY_DATABASE_URI"] = config.DATABASE_URL
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=86400,
    )

    # Rate limiter
    limiter = Limiter(get_remote_address, app=app, default_limits=[])

    # Init DB
    db.init_app(app)
    with app.app_context():
        db.create_all()
        # Migrate: add project_id column to scan_history if missing
        from sqlalchemy import text
        try:
            db.session.execute(text(
                "ALTER TABLE scan_history ADD COLUMN IF NOT EXISTS "
                "project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL"
            ))
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            log.info("project_id migration skipped (may already exist): %s", e)

        # Migrate: add user profile columns if missing
        profile_cols = [
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name VARCHAR(120)",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS company VARCHAR(120)",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS phone VARCHAR(30)",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS birthday DATE",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS address TEXT",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_tier VARCHAR(20) NOT NULL DEFAULT 'free'",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS upload_limit_mb INTEGER NOT NULL DEFAULT 200",
        ]
        try:
            for stmt in profile_cols:
                db.session.execute(text(stmt))
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            log.info("Profile column migration skipped (may already exist): %s", e)

    # Bootstrap admin
    bootstrap_admin(app)

    # Mark stale "running" scans as interrupted (from previous container lifecycle)
    with app.app_context():
        stale = ScanHistory.query.filter_by(status="running").all()
        for s in stale:
            s.status = "interrupted"
            s.completed_at = datetime.now(timezone.utc)
        if stale:
            db.session.commit()
            log.info("Marked %d stale running scans as interrupted", len(stale))

    # Ensure data dirs
    os.makedirs(config.REPORTS_DIR, exist_ok=True)
    os.makedirs(config.UPLOADS_DIR, exist_ok=True)
    os.makedirs(config.SUBMISSIONS_DIR, exist_ok=True)
    os.makedirs(config.PRESETS_DIR, exist_ok=True)

    # One-time migration: copy baked-in presets to data volume
    if os.path.isdir(config.PRESETS_BAKED_DIR) and config.PRESETS_BAKED_DIR != config.PRESETS_DIR:
        if not os.listdir(config.PRESETS_DIR):
            try:
                shutil.copytree(config.PRESETS_BAKED_DIR, config.PRESETS_DIR, dirs_exist_ok=True)
                log.info("Migrated baked-in presets to data volume: %s", config.PRESETS_DIR)
            except Exception as e:
                log.warning("Preset migration failed: %s", e)

    # ── Project migration (idempotent) ────────────────────
    def _migrate_projects():
        """Create Default project for each user and move flat files into project dirs."""
        users = User.query.all()
        for u in users:
            # Ensure Default project exists
            default = Project.query.filter_by(user_id=u.id, name="Default").first()
            if not default:
                default = Project(user_id=u.id, name="Default")
                db.session.add(default)
                db.session.flush()
                log.info("Created Default project for user %s (id=%d)", u.username, default.id)

            # Move flat uploads into project subdir
            user_up = os.path.join(config.UPLOADS_DIR, str(u.id))
            proj_up = os.path.join(user_up, str(default.id))
            if os.path.isdir(user_up):
                os.makedirs(proj_up, exist_ok=True)
                for fn in os.listdir(user_up):
                    src = os.path.join(user_up, fn)
                    if os.path.isfile(src) and fn.lower().endswith((".pcap", ".pcapng", ".cap")):
                        dst = os.path.join(proj_up, fn)
                        if not os.path.exists(dst):
                            shutil.move(src, dst)
                            log.info("Migrated upload %s -> project %d", fn, default.id)

            # Move flat reports into project subdir
            user_rp = os.path.join(config.REPORTS_DIR, str(u.id))
            proj_rp = os.path.join(user_rp, str(default.id))
            if os.path.isdir(user_rp):
                os.makedirs(proj_rp, exist_ok=True)
                for fn in os.listdir(user_rp):
                    src = os.path.join(user_rp, fn)
                    if os.path.isfile(src) and fn.lower().endswith(".json"):
                        dst = os.path.join(proj_rp, fn)
                        if not os.path.exists(dst):
                            shutil.move(src, dst)
                            log.info("Migrated report %s -> project %d", fn, default.id)

            # Update scan history records that have no project_id
            ScanHistory.query.filter_by(user_id=u.id, project_id=None).update(
                {"project_id": default.id}
            )

        db.session.commit()

    with app.app_context():
        try:
            _migrate_projects()
        except Exception as e:
            log.warning("Project migration error (may be first run): %s", e)
            db.session.rollback()

    # ── Per-user directory helpers (project-aware) ────────
    def _ensure_default_project(user_id):
        """Get or create the Default project for a user."""
        proj = Project.query.filter_by(user_id=user_id, name="Default").first()
        if not proj:
            proj = Project(user_id=user_id, name="Default")
            db.session.add(proj)
            db.session.commit()
        return proj

    def user_uploads_dir(project_id=None):
        uid = str(session["user_id"])
        if project_id is None:
            default = _ensure_default_project(session["user_id"])
            project_id = default.id
        d = os.path.join(config.UPLOADS_DIR, uid, str(project_id))
        os.makedirs(d, exist_ok=True)
        return d

    def user_reports_dir(project_id=None):
        uid = str(session["user_id"])
        if project_id is None:
            default = _ensure_default_project(session["user_id"])
            project_id = default.id
        d = os.path.join(config.REPORTS_DIR, uid, str(project_id))
        os.makedirs(d, exist_ok=True)
        return d

    # Expose feature flags to templates
    @app.context_processor
    def inject_features():
        return {
            "enable_live_capture": config.ENABLE_LIVE_CAPTURE,
            "app_version": APP_VERSION,
        }

    # ── CSRF origin check ─────────────────────────────────────

    @app.before_request
    def csrf_check():
        if request.method in ('POST', 'PUT', 'DELETE'):
            origin = request.headers.get('Origin') or ''
            referer = request.headers.get('Referer') or ''
            expected_host = request.host.split(':')[0]
            origin_host = urlparse(origin).hostname if origin else None
            referer_host = urlparse(referer).hostname if referer else None
            if expected_host not in (origin_host, referer_host):
                return jsonify({"error": "Origin check failed"}), 403

    # ── Auth routes ──────────────────────────────────────────

    @app.route("/login", methods=["GET"])
    def login_page():
        if "user" in session:
            return redirect(url_for("dashboard"))
        return render_template("login.html")

    @app.route("/login", methods=["POST"])
    @limiter.limit("5 per minute")
    def login_submit():
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = verify_user(username, password)
        if not user:
            log.warning("Failed login for '%s' from %s", username, request.remote_addr)
            return render_template("login.html", error="Invalid credentials")
        log.info("Login: %s from %s", username, request.remote_addr)
        session["user"] = user.username
        session["user_id"] = user.id
        session["role"] = user.role
        return redirect(url_for("dashboard"))

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login_page"))

    # ── Landing / About / Demo ────────────────────────────────

    @app.route("/")
    def landing_page():
        if "user" in session:
            return redirect(url_for("dashboard"))
        return render_template("landing.html")

    @app.route("/about")
    def about_page():
        return render_template("about.html")

    # ── Dashboard ────────────────────────────────────────────

    @app.route("/dashboard")
    @login_required
    def dashboard():
        return render_template("dashboard.html")

    @app.route("/reports")
    @login_required
    def reports_page():
        return render_template("reports.html")

    @app.route("/scans")
    @login_required
    def scans_page():
        return render_template("scans.html")

    # ── Projects page ────────────────────────────────────────

    @app.route("/projects")
    @login_required
    def projects_page():
        return render_template("projects.html")

    # ── Project CRUD API ─────────────────────────────────────

    @app.route("/api/projects")
    @login_required
    def api_projects_list():
        projects = Project.query.filter_by(user_id=session["user_id"]).order_by(Project.created_at).all()
        result = []
        for p in projects:
            up_dir = os.path.join(config.UPLOADS_DIR, str(session["user_id"]), str(p.id))
            rp_dir = os.path.join(config.REPORTS_DIR, str(session["user_id"]), str(p.id))
            pcap_count = 0
            report_count = 0
            if os.path.isdir(up_dir):
                pcap_count = sum(1 for f in os.listdir(up_dir)
                                 if f.lower().endswith((".pcap", ".pcapng", ".cap")))
            if os.path.isdir(rp_dir):
                report_count = sum(1 for f in os.listdir(rp_dir) if f.endswith(".json"))
            result.append({
                "id": p.id,
                "name": p.name,
                "pcap_count": pcap_count,
                "report_count": report_count,
                "created_at": p.created_at.isoformat() if p.created_at else None,
            })
        return jsonify({"projects": result})

    @app.route("/api/projects", methods=["POST"])
    @login_required
    def api_projects_create():
        body = request.get_json(silent=True) or {}
        name = body.get("name", "").strip()
        if not name:
            return jsonify({"ok": False, "error": "Project name required"}), 400
        if len(name) > 200:
            return jsonify({"ok": False, "error": "Name too long (max 200 chars)"}), 400
        existing = Project.query.filter_by(user_id=session["user_id"], name=name).first()
        if existing:
            return jsonify({"ok": False, "error": "Project name already exists"}), 409
        proj = Project(user_id=session["user_id"], name=name)
        db.session.add(proj)
        db.session.commit()
        return jsonify({"ok": True, "id": proj.id, "name": proj.name})

    @app.route("/api/projects/<int:pid>", methods=["PUT"])
    @login_required
    def api_projects_rename(pid):
        proj = Project.query.filter_by(id=pid, user_id=session["user_id"]).first()
        if not proj:
            return jsonify({"ok": False, "error": "Project not found"}), 404
        if proj.name == "Default":
            return jsonify({"ok": False, "error": "Cannot rename the Default project"}), 400
        body = request.get_json(silent=True) or {}
        name = body.get("name", "").strip()
        if not name:
            return jsonify({"ok": False, "error": "Project name required"}), 400
        if len(name) > 200:
            return jsonify({"ok": False, "error": "Name too long (max 200 chars)"}), 400
        dup = Project.query.filter_by(user_id=session["user_id"], name=name).first()
        if dup and dup.id != pid:
            return jsonify({"ok": False, "error": "Project name already exists"}), 409
        proj.name = name
        db.session.commit()
        return jsonify({"ok": True})

    @app.route("/api/projects/<int:pid>", methods=["DELETE"])
    @login_required
    def api_projects_delete(pid):
        if request.args.get("confirm") != "true":
            return jsonify({"ok": False, "error": "Add ?confirm=true to delete"}), 400
        proj = Project.query.filter_by(id=pid, user_id=session["user_id"]).first()
        if not proj:
            return jsonify({"ok": False, "error": "Project not found"}), 404
        if proj.name == "Default":
            return jsonify({"ok": False, "error": "Cannot delete the Default project"}), 400

        # Delete files on disk
        uid = str(session["user_id"])
        up_dir = os.path.join(config.UPLOADS_DIR, uid, str(pid))
        rp_dir = os.path.join(config.REPORTS_DIR, uid, str(pid))
        if os.path.isdir(up_dir):
            shutil.rmtree(up_dir, ignore_errors=True)
        if os.path.isdir(rp_dir):
            shutil.rmtree(rp_dir, ignore_errors=True)

        # SET NULL on scans (handled by FK ondelete, but be explicit)
        ScanHistory.query.filter_by(project_id=pid, user_id=session["user_id"]).update(
            {"project_id": None}
        )
        db.session.delete(proj)
        db.session.commit()
        return jsonify({"ok": True})

    @app.route("/api/projects/<int:pid>/files")
    @login_required
    def api_project_files(pid):
        proj = Project.query.filter_by(id=pid, user_id=session["user_id"]).first()
        if not proj:
            return jsonify({"error": "Project not found"}), 404
        files = []
        udir = os.path.join(config.UPLOADS_DIR, str(session["user_id"]), str(pid))
        if os.path.isdir(udir):
            for fn in os.listdir(udir):
                if not fn.lower().endswith((".pcap", ".pcapng", ".cap")):
                    continue
                path = os.path.join(udir, fn)
                try:
                    stat = os.stat(path)
                    files.append({
                        "name": fn,
                        "size": stat.st_size,
                        "modified": datetime.fromtimestamp(
                            stat.st_mtime, tz=timezone.utc
                        ).isoformat(),
                    })
                except Exception:
                    pass
        files.sort(key=lambda f: f["modified"], reverse=True)
        return jsonify({"files": files})

    @app.route("/api/projects/<int:pid>/reports")
    @login_required
    def api_project_reports(pid):
        proj = Project.query.filter_by(id=pid, user_id=session["user_id"]).first()
        if not proj:
            return jsonify({"error": "Project not found"}), 404
        reports = []
        rdir = os.path.join(config.REPORTS_DIR, str(session["user_id"]), str(pid))
        if os.path.isdir(rdir):
            for fn in os.listdir(rdir):
                if fn.endswith(".json"):
                    path = os.path.join(rdir, fn)
                    try:
                        stat = os.stat(path)
                        reports.append({
                            "filename": fn,
                            "size": stat.st_size,
                            "modified": datetime.fromtimestamp(
                                stat.st_mtime, tz=timezone.utc
                            ).isoformat(),
                        })
                    except Exception:
                        pass
        reports.sort(key=lambda r: r["modified"], reverse=True)
        return jsonify({"reports": reports})

    @app.route("/api/projects/<int:pid>/upload", methods=["POST"])
    @login_required
    @limiter.limit("10 per minute")
    def api_project_upload(pid):
        proj = Project.query.filter_by(id=pid, user_id=session["user_id"]).first()
        if not proj:
            return jsonify({"ok": False, "error": "Project not found"}), 404
        return _handle_upload(pid)

    @app.route("/api/projects/<int:pid>/files/<filename>", methods=["DELETE"])
    @login_required
    def api_project_file_delete(pid, filename):
        proj = Project.query.filter_by(id=pid, user_id=session["user_id"]).first()
        if not proj:
            return jsonify({"ok": False, "error": "Project not found"}), 404
        safe_name = os.path.basename(filename)
        path = os.path.join(config.UPLOADS_DIR, str(session["user_id"]), str(pid), safe_name)
        if os.path.isfile(path):
            os.unlink(path)
        return jsonify({"ok": True})

    # ── Upload pipeline (shared logic) ───────────────────────

    def _handle_upload(project_id=None):
        """Core upload handler with magic-byte validation, size limits, auto-slice, and archival."""
        if "file" not in request.files:
            return jsonify({"ok": False, "error": "No file part"}), 400
        f = request.files["file"]
        if not f.filename:
            return jsonify({"ok": False, "error": "No file selected"}), 400

        # Per-user upload limit (falls back to global default)
        _uploader = User.query.get(session["user_id"])
        _limit_mb = (_uploader.upload_limit_mb if _uploader and _uploader.upload_limit_mb else 200)
        user_max_size = _limit_mb * 1024 * 1024

        # Check content length hint
        content_length = request.content_length or 0
        if content_length > user_max_size:
            return jsonify({
                "ok": False,
                "error": f"File too large (max {_limit_mb} MB)",
            }), 413

        safe_name = os.path.basename(f.filename)

        # Resolve project
        if project_id is None:
            project_id_str = request.form.get("project_id", "")
            if project_id_str:
                try:
                    project_id = int(project_id_str)
                    proj = Project.query.filter_by(id=project_id, user_id=session["user_id"]).first()
                    if not proj:
                        return jsonify({"ok": False, "error": "Project not found"}), 404
                except (ValueError, TypeError):
                    project_id = None

        if project_id is None:
            default = _ensure_default_project(session["user_id"])
            project_id = default.id

        dest_dir = user_uploads_dir(project_id)

        # Stream to temp file with magic-byte check and size enforcement
        import tempfile
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".pcap", dir=dest_dir)
        written = 0
        magic_checked = False
        try:
            with os.fdopen(tmp_fd, "wb") as out:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    # Check magic bytes after first chunk
                    if not magic_checked:
                        if len(chunk) < 4:
                            # Read more to get at least 4 bytes
                            chunk += f.read(4 - len(chunk))
                        if len(chunk) < 4 or chunk[:4] not in PCAP_MAGIC:
                            os.unlink(tmp_path)
                            return jsonify({
                                "ok": False,
                                "error": "Not a valid PCAP file",
                            }), 400
                        magic_checked = True

                    written += len(chunk)
                    if written > user_max_size:
                        os.unlink(tmp_path)
                        return jsonify({
                            "ok": False,
                            "error": f"File too large (max {_limit_mb} MB)",
                        }), 413
                    out.write(chunk)
        except Exception:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise

        if written == 0:
            os.unlink(tmp_path)
            return jsonify({"ok": False, "error": "Empty file"}), 400

        # Archive full file in background (TOS compliance)
        archive_src = tmp_path  # Will be moved, so archive first if needed
        user_id = session["user_id"]
        username = session.get("user", "unknown")

        # Auto-slice if > PCAP_PROCESS_SIZE
        trimmed = False
        original_size = written
        final_path = os.path.join(dest_dir, safe_name)

        if written > config.PCAP_PROCESS_SIZE:
            # Truncate to PCAP_PROCESS_SIZE for processing
            trimmed = True
            # Simple byte-level truncation then repair with editcap if available
            sliced_path = final_path + ".slicing"
            try:
                with open(tmp_path, "rb") as fin, open(sliced_path, "wb") as fout:
                    remaining = config.PCAP_PROCESS_SIZE
                    while remaining > 0:
                        chunk = fin.read(min(65536, remaining))
                        if not chunk:
                            break
                        fout.write(chunk)
                        remaining -= len(chunk)

                # Try editcap to repair trailing truncated packet
                try:
                    repaired_path = final_path + ".repaired"
                    result = subprocess.run(
                        ["editcap", sliced_path, repaired_path],
                        capture_output=True, timeout=30,
                    )
                    if result.returncode == 0 and os.path.isfile(repaired_path):
                        os.rename(repaired_path, final_path)
                        os.unlink(sliced_path)
                    else:
                        # editcap failed, use raw truncated version
                        os.rename(sliced_path, final_path)
                        if os.path.exists(repaired_path):
                            os.unlink(repaired_path)
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    # editcap not available, use raw truncated version
                    os.rename(sliced_path, final_path)
            except Exception:
                # Fallback: just use the full file
                trimmed = False
                os.rename(tmp_path, final_path)
                if os.path.exists(sliced_path):
                    os.unlink(sliced_path)
        else:
            os.rename(tmp_path, final_path)

        trimmed_size = os.path.getsize(final_path) if os.path.isfile(final_path) else written

        # Background archive of full original
        archive_path = tmp_path if trimmed and os.path.isfile(tmp_path) else final_path
        threading.Thread(
            target=_archive_submission,
            args=(archive_path, user_id, username, safe_name),
            daemon=True,
            name="archive-submission",
        ).start()

        # Clean up temp file if we sliced (archive thread reads it, give it a moment)
        if trimmed and os.path.isfile(tmp_path) and tmp_path != final_path:
            def _delayed_cleanup():
                time.sleep(30)
                try:
                    if os.path.isfile(tmp_path):
                        os.unlink(tmp_path)
                except Exception:
                    pass
            threading.Thread(target=_delayed_cleanup, daemon=True).start()

        log.info("Upload: %s by %s (%d bytes)", safe_name, session.get("user", "?"), trimmed_size)
        resp = {
            "ok": True,
            "filename": safe_name,
            "size": trimmed_size,
            "project_id": project_id,
        }
        if trimmed:
            resp["trimmed"] = True
            resp["original_size"] = original_size
            resp["trimmed_size"] = trimmed_size
        return jsonify(resp)

    # ── Scan start ───────────────────────────────────────────

    @app.route("/api/scans/start", methods=["POST"])
    @login_required
    @limiter.limit("10 per minute")
    def api_scan_start():
        body = request.get_json(silent=True) or {}
        command = body.get("command", "chain")
        # Accept pcap_file (bare filename) with pcap_path backward compat
        pcap_file = body.get("pcap_file", "") or body.get("pcap_path", "")
        interface = body.get("interface", "")
        duration = body.get("duration", "")
        skip_ephemeral = body.get("skip_ephemeral", False)
        capture_filter = body.get("capture_filter", "")
        chunk_size = body.get("chunk_size", 300000)
        collapse_threshold = body.get("collapse_threshold", 50)
        project_id = body.get("project_id")

        # Resolve project
        if project_id is not None:
            try:
                project_id = int(project_id)
                proj = Project.query.filter_by(id=project_id, user_id=session["user_id"]).first()
                if not proj:
                    return jsonify({"ok": False, "error": "Project not found"}), 404
            except (ValueError, TypeError):
                project_id = None

        if project_id is None:
            default = _ensure_default_project(session["user_id"])
            project_id = default.id

        # Resolve pcap_file to full path
        pcap_path = ""
        if pcap_file:
            if pcap_file.startswith("preset:"):
                # Preset file — resolve from presets directory (category/filename)
                preset_rel = pcap_file[7:]
                try:
                    presets_root = Path(config.PRESETS_DIR).resolve()
                    requested = (presets_root / preset_rel).resolve()
                    if not str(requested).startswith(str(presets_root) + os.sep) and requested != presets_root:
                        return jsonify({"ok": False, "error": "Invalid preset"}), 400
                    pcap_path = str(requested)
                except (ValueError, OSError):
                    return jsonify({"ok": False, "error": "Invalid preset"}), 400
            else:
                # User file — resolve from uploads directory
                pcap_path = os.path.join(user_uploads_dir(project_id), os.path.basename(pcap_file))
                # Fallback: search presets subdirs for bare filename (retry support)
                if not os.path.isfile(pcap_path) and os.path.isdir(config.PRESETS_DIR):
                    bare = os.path.basename(pcap_file)
                    presets_root = Path(config.PRESETS_DIR).resolve()
                    for cat in os.listdir(config.PRESETS_DIR):
                        candidate = (presets_root / cat / bare).resolve()
                        if str(candidate).startswith(str(presets_root) + os.sep) and candidate.is_file():
                            pcap_path = str(candidate)
                            break
            if not os.path.isfile(pcap_path):
                return jsonify({"ok": False, "error": "File not found"}), 404

        with _runs_lock:
            active = _get_active_runs()
            if len(active) >= MAX_CONCURRENT_SCANS:
                return jsonify({
                    "ok": False,
                    "error": f"Maximum {MAX_CONCURRENT_SCANS} concurrent scans reached",
                    "active_run_ids": [r[0] for r in active],
                }), 409
            _cleanup_runs()

        run_id = str(uuid.uuid4())
        # Prefix report with original PCAP filename (sanitised)
        pcap_stem = ""
        if pcap_path:
            pcap_stem = os.path.splitext(os.path.basename(pcap_path))[0]
            pcap_stem = re.sub(r'[^a-zA-Z0-9._-]', '_', pcap_stem)[:60]
        elif interface:
            pcap_stem = interface
        prefix = f"{pcap_stem}-" if pcap_stem else ""
        report_filename = f"{prefix}marlinspike-{run_id[:8]}.json"
        report_path = os.path.join(user_reports_dir(project_id), report_filename)

        # Build CLI args
        args = ["python3", "-u", config.MARLINSPIKE_PY]
        if pcap_path:
            args.extend(["--pcap", pcap_path])
        elif interface:
            args.extend(["--interface", interface])
            if duration:
                args.extend(["--capture-duration", str(duration)])
        if skip_ephemeral:
            args.append("--skip-ephemeral")
        if capture_filter:
            args.extend(["--capture-filter", capture_filter])
        try:
            chunk_val = int(chunk_size)
            if chunk_val > 0:
                args.extend(["--chunk-size", str(chunk_val)])
        except (ValueError, TypeError):
            pass
        try:
            collapse_val = int(collapse_threshold)
            if collapse_val > 0:
                args.extend(["--collapse-threshold", str(collapse_val)])
            else:
                args.extend(["--collapse-threshold", "0"])
        except (ValueError, TypeError):
            pass
        args.append("--no-grassmarlin")
        args.extend(["-o", report_path])
        args.append(command)

        # MarlinSpike chain stages
        chain_stages = ["Ingest", "Analyze", "Classify", "Report"]
        stages = []
        for i, stage_name in enumerate(chain_stages):
            stages.append({
                "number": i + 1,
                "name": stage_name,
                "state": "pending",
            })

        try:
            proc = subprocess.Popen(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=config.REPORTS_DIR,
            )
        except Exception as e:
            log.error("Failed to start scan: %s", e)
            return jsonify({"ok": False, "error": "Failed to start scan"}), 500

        # Compute PCAP hash if file-based
        pcap_hash = None
        pcap_source = (os.path.basename(pcap_path) if pcap_path else None) or (f"live:{interface}" if interface else None)
        if pcap_path and os.path.isfile(pcap_path):
            try:
                h = hashlib.sha256()
                with open(pcap_path, "rb") as pf:
                    for chunk in iter(lambda: pf.read(65536), b""):
                        h.update(chunk)
                pcap_hash = h.hexdigest()
            except Exception:
                pass

        log.info("Scan start: %s by %s (command=%s, file=%s)", run_id, session.get("user", "?"), command, pcap_source or "live")

        run_state = {
            "process": proc,
            "output": [],
            "status": "running",
            "stage": 0,
            "stage_name": "",
            "stages": stages,
            "command": command,
            "report_path": report_path,
            "report_filename": report_filename,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "finished_at": None,
            "return_code": None,
            "artifacts_produced": {},
            "project_id": project_id,
        }

        with _runs_lock:
            _run_registry[run_id] = run_state

        # Persist to scan_history
        scan_record = ScanHistory(
            run_id=run_id,
            user_id=session["user_id"],
            project_id=project_id,
            command=command,
            pcap_source=pcap_source,
            pcap_hash=pcap_hash,
            status="running",
            report_path=report_path,
        )
        db.session.add(scan_record)
        db.session.commit()

        def _reader():
            for line in proc.stdout:
                line = line.rstrip()
                run_state["output"].append(line)
                # Parse stage markers
                m = re.match(r"^\s*STAGE\s+(\d+)\s*[—–-]\s*(.+)", line)
                if m:
                    stage_num = int(m.group(1))
                    stage_name = m.group(2).strip()
                    run_state["stage"] = stage_num
                    run_state["stage_name"] = stage_name
                    for s in run_state["stages"]:
                        if s["number"] < stage_num:
                            s["state"] = "complete"
                        elif s["number"] == stage_num:
                            s["state"] = "running"
                # Detect errors
                if re.search(r"\[!\].*(?:FAILED|ERROR)", line, re.IGNORECASE):
                    for s in run_state["stages"]:
                        if s["state"] == "running":
                            s["state"] = "failed"
                            break
            proc.wait()
            run_state["return_code"] = proc.returncode
            run_state["finished_at"] = datetime.now(timezone.utc).isoformat()
            if proc.returncode == 0:
                run_state["status"] = "completed"
                for s in run_state["stages"]:
                    if s["state"] in ("running", "complete"):
                        s["state"] = "complete"
            else:
                run_state["status"] = "failed"
                for s in run_state["stages"]:
                    if s["state"] == "running":
                        s["state"] = "failed"
            _scan_artifacts(run_state)

            # Update scan_history in DB
            try:
                with app.app_context():
                    rec = ScanHistory.query.filter_by(run_id=run_id).first()
                    if rec:
                        rec.status = run_state["status"]
                        rec.completed_at = datetime.now(timezone.utc)
                        # Save last output lines on failure
                        if run_state["status"] in ("failed", "stopped"):
                            tail = run_state["output"][-10:]
                            rec.error_tail = "\n".join(tail) if tail else None
                        # Read report for node/edge counts
                        if os.path.isfile(report_path):
                            try:
                                with open(report_path) as rf:
                                    rdata = json.load(rf)
                                topo = rdata.get("results", {}).get("topology", rdata.get("topology", {}))
                                rec.node_count = len(topo.get("nodes", []))
                                rec.edge_count = len(topo.get("edges", []))
                            except Exception:
                                pass
                        db.session.commit()
            except Exception as e:
                log.warning("Failed to update scan_history: %s", e)

        threading.Thread(target=_reader, daemon=True, name=f"ms-run-{run_id[:8]}").start()

        return jsonify({"ok": True, "run_id": run_id})

    # ── Run status/output/stop/list ──────────────────────────

    @app.route("/api/runs")
    @login_required
    def api_runs_list():
        with _runs_lock:
            _cleanup_runs()
            active = []
            recent = []
            for run_id, run in _run_registry.items():
                entry = {
                    "run_id": run_id,
                    "command": run["command"],
                    "status": run["status"],
                    "stage": run["stage"],
                    "stage_name": run["stage_name"],
                    "stages": run.get("stages", []),
                    "started_at": run["started_at"],
                    "finished_at": run["finished_at"],
                    "output_lines": len(run["output"]),
                    "report_filename": run["report_filename"],
                }
                if run["status"] in ("pending", "running"):
                    active.append(entry)
                else:
                    recent.append(entry)
        return jsonify({"active": active, "recent": recent})

    @app.route("/api/runs/<run_id>/status")
    @login_required
    def api_run_status(run_id):
        with _runs_lock:
            run = _run_registry.get(run_id)
        if not run:
            return jsonify({"error": "Run not found"}), 404
        return jsonify({
            "run_id": run_id,
            "status": run["status"],
            "stage": run["stage"],
            "stage_name": run["stage_name"],
            "stages": run.get("stages", []),
            "command": run["command"],
            "started_at": run["started_at"],
            "finished_at": run["finished_at"],
            "return_code": run["return_code"],
            "output_lines": len(run["output"]),
            "report_filename": run["report_filename"],
            "project_id": run.get("project_id"),
        })

    @app.route("/api/runs/<run_id>/output")
    @login_required
    def api_run_output(run_id):
        with _runs_lock:
            run = _run_registry.get(run_id)
        if not run:
            return jsonify({"error": "Run not found"}), 404
        from_idx = request.args.get("from", None, type=int)
        if from_idx is None:
            from_idx = request.args.get("since", 0, type=int)
        raw_lines = run["output"][from_idx:]
        total = len(run["output"])
        # Sanitize output — strip paths, tool names, internal details
        sanitized = []
        for line in raw_lines:
            line = re.sub(r"/[\w/.-]+/([^/\s]+)", r"\1", line)  # strip directory paths
            line = re.sub(r"\btshark\b", "analyzer", line, flags=re.IGNORECASE)
            line = re.sub(r"\bcapinfos?\b", "analyzer", line, flags=re.IGNORECASE)
            line = re.sub(r"\beditcap\b", "preprocessor", line, flags=re.IGNORECASE)
            sanitized.append(line)
        return jsonify({
            "lines": sanitized,
            "next_from": total,
            "total": total,
            "status": run["status"],
        })

    @app.route("/api/runs/<run_id>/stop", methods=["POST"])
    @login_required
    def api_run_stop(run_id):
        with _runs_lock:
            run = _run_registry.get(run_id)
        if not run:
            return jsonify({"error": "Run not found"}), 404
        proc = run.get("process")
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()
            run["status"] = "stopped"
            run["finished_at"] = datetime.now(timezone.utc).isoformat()
            for s in run.get("stages", []):
                if s["state"] == "running":
                    s["state"] = "stopped"
            # Update DB
            try:
                rec = ScanHistory.query.filter_by(run_id=run_id).first()
                if rec:
                    rec.status = "stopped"
                    rec.completed_at = datetime.now(timezone.utc)
                    db.session.commit()
            except Exception:
                pass
        return jsonify({"ok": True})

    # ── Run topology + live viewer ───────────────────────────

    @app.route("/api/runs/<run_id>/topology")
    @login_required
    def api_run_topology(run_id):
        with _runs_lock:
            run = _run_registry.get(run_id)
        if not run:
            return jsonify({"error": "Run not found"}), 404
        report_path = run.get("report_path", "")
        if not os.path.isfile(report_path):
            return jsonify({
                "status": run["status"],
                "stage": run["stage"],
                "report_filename": run.get("report_filename", ""),
                "topology": {"nodes": [], "edges": []},
                "has_data": False,
            })
        try:
            with open(report_path) as f:
                report = json.load(f)
            topo = report.get("topology", {})
            nodes = topo.get("nodes", report.get("nodes", []))
            edges = topo.get("edges", report.get("edges", []))
            return jsonify({
                "status": run["status"],
                "stage": run["stage"],
                "stage_name": run["stage_name"],
                "stages": run.get("stages", []),
                "report_filename": run.get("report_filename", ""),
                "capture_info": report.get("capture_info"),
                "protocol_summary": report.get("protocol_summary", {}),
                "risk_findings": report.get("risk_findings", []),
                "topology": {"nodes": nodes, "edges": edges},
                "node_count": len(nodes),
                "edge_count": len(edges),
                "has_data": len(nodes) > 0,
                "completed_stages": report.get("completed_stages", []),
            })
        except Exception as e:
            log.error("Failed to read report: %s", e)
            return jsonify({"error": "Failed to read report"}), 500

    @app.route("/api/runs/<run_id>/live")
    @login_required
    def api_run_live_viewer(run_id):
        with _runs_lock:
            run = _run_registry.get(run_id)
        if not run:
            return "Run not found", 404
        return render_template("live.html", run_id=run_id)

    # ── Reports ──────────────────────────────────────────────

    @app.route("/api/reports")
    @login_required
    def api_reports_list():
        project_id = request.args.get("project_id", None, type=int)
        limit = request.args.get("limit", None, type=int)
        reports = []
        rdir = user_reports_dir(project_id)
        if os.path.isdir(rdir):
            for fn in os.listdir(rdir):
                if fn.endswith(".json"):
                    path = os.path.join(rdir, fn)
                    try:
                        stat = os.stat(path)
                        size = stat.st_size
                        mtime_ts = stat.st_mtime
                        mtime = datetime.fromtimestamp(
                            mtime_ts, tz=timezone.utc
                        ).isoformat()
                    except Exception:
                        size = 0
                        mtime_ts = 0
                        mtime = ""
                    reports.append({"filename": fn, "size": size, "modified": mtime, "_sort": mtime_ts})
            reports.sort(key=lambda r: r.pop("_sort"), reverse=True)
        total = len(reports)
        if limit and limit > 0:
            reports = reports[:limit]
        return jsonify({"reports": reports, "total": total})

    @app.route("/api/reports/diff")
    @login_required
    def api_report_diff():
        a_name = os.path.basename(request.args.get("a", ""))
        b_name = os.path.basename(request.args.get("b", ""))
        project_id = request.args.get("project_id", None, type=int)
        if not a_name or not b_name:
            return "Missing ?a= and ?b= parameters", 400
        rdir = user_reports_dir(project_id)
        a_path = os.path.join(rdir, a_name)
        b_path = os.path.join(rdir, b_name)
        if not os.path.isfile(a_path):
            return f"Report A not found: {a_name}", 404
        if not os.path.isfile(b_path):
            return f"Report B not found: {b_name}", 404

        with open(a_path) as f:
            report_a = json.load(f)
        with open(b_path) as f:
            report_b = json.load(f)

        topo_a = report_a.get("results", {}).get("topology", report_a.get("topology", {}))
        topo_b = report_b.get("results", {}).get("topology", report_b.get("topology", {}))
        nodes_a = {n["ip"]: n for n in topo_a.get("nodes", []) if n.get("ip")}
        nodes_b = {n["ip"]: n for n in topo_b.get("nodes", []) if n.get("ip")}
        edges_a = topo_a.get("edges", [])
        edges_b = topo_b.get("edges", [])

        # Node diff
        all_ips = set(nodes_a.keys()) | set(nodes_b.keys())
        node_diffs = []
        for ip in sorted(all_ips):
            a_node = nodes_a.get(ip)
            b_node = nodes_b.get(ip)
            if a_node and not b_node:
                node_diffs.append({"ip": ip, "diff": "removed", "a": a_node, "b": None, "changes": []})
            elif b_node and not a_node:
                node_diffs.append({"ip": ip, "diff": "added", "a": None, "b": b_node, "changes": []})
            else:
                changes = []
                for field in ("role", "vendor", "purdue_level"):
                    va = a_node.get(field)
                    vb = b_node.get(field)
                    if va != vb:
                        changes.append({"field": field, "from": va, "to": vb})
                pa = set(a_node.get("protocols", []))
                pb = set(b_node.get("protocols", []))
                if pa != pb:
                    changes.append({
                        "field": "protocols",
                        "added": sorted(pb - pa),
                        "removed": sorted(pa - pb),
                    })
                diff_type = "changed" if changes else "unchanged"
                node_diffs.append({"ip": ip, "diff": diff_type, "a": a_node, "b": b_node, "changes": changes})

        # Edge diff
        def edge_key(e):
            return (e.get("src", ""), e.get("dst", ""), e.get("protocol", ""))

        ea_set = {edge_key(e): e for e in edges_a}
        eb_set = {edge_key(e): e for e in edges_b}
        all_edges = set(ea_set.keys()) | set(eb_set.keys())
        edge_diffs = []
        for ek in sorted(all_edges):
            a_e = ea_set.get(ek)
            b_e = eb_set.get(ek)
            if a_e and not b_e:
                edge_diffs.append({"key": list(ek), "diff": "removed", "a": a_e, "b": None})
            elif b_e and not a_e:
                edge_diffs.append({"key": list(ek), "diff": "added", "a": None, "b": b_e})
            else:
                edge_diffs.append({"key": list(ek), "diff": "unchanged", "a": a_e, "b": b_e})

        summary = {
            "nodes_added": sum(1 for n in node_diffs if n["diff"] == "added"),
            "nodes_removed": sum(1 for n in node_diffs if n["diff"] == "removed"),
            "nodes_changed": sum(1 for n in node_diffs if n["diff"] == "changed"),
            "nodes_unchanged": sum(1 for n in node_diffs if n["diff"] == "unchanged"),
            "edges_added": sum(1 for e in edge_diffs if e["diff"] == "added"),
            "edges_removed": sum(1 for e in edge_diffs if e["diff"] == "removed"),
            "edges_unchanged": sum(1 for e in edge_diffs if e["diff"] == "unchanged"),
        }

        diff_data = {
            "a_name": a_name,
            "b_name": b_name,
            "a_time": report_a.get("timestamp", ""),
            "b_time": report_b.get("timestamp", ""),
            "summary": summary,
            "nodes": node_diffs,
            "edges": edge_diffs,
        }

        return render_template("diff.html", diff=diff_data, diff_json=diff_data)

    @app.route("/api/reports/<filename>")
    @login_required
    def api_report_download(filename):
        safe_name = os.path.basename(filename)
        project_id = request.args.get("project_id", None, type=int)
        path = os.path.join(user_reports_dir(project_id), safe_name)
        if not os.path.isfile(path):
            return jsonify({"error": "Report not found"}), 404
        return send_file(path, as_attachment=True, download_name=safe_name)

    @app.route("/api/reports/<filename>/viewer")
    @login_required
    def api_report_viewer(filename):
        safe_name = os.path.basename(filename)
        project_id = request.args.get("project_id", None, type=int)
        path = os.path.join(user_reports_dir(project_id), safe_name)
        if not os.path.isfile(path):
            return "Report not found", 404
        with open(path) as f:
            report = json.load(f)
        sanitized_report = _sanitize_report(report)
        return render_template(
            "viewer.html",
            report=sanitized_report,
            report_json=sanitized_report,
            viewer_context=_build_viewer_context(sanitized_report),
            filename=safe_name,
        )

    @app.route("/api/reports/<filename>/assets")
    @login_required
    def api_report_assets(filename):
        safe_name = os.path.basename(filename)
        project_id = request.args.get("project_id", None, type=int)
        path = os.path.join(user_reports_dir(project_id), safe_name)
        if not os.path.isfile(path):
            return "Report not found", 404
        with open(path) as f:
            report = json.load(f)
        return render_template(
            "assets.html",
            report_json=_sanitize_report(report),
            filename=safe_name,
        )

    @app.route("/api/reports/<filename>", methods=["DELETE"])
    @login_required
    def api_report_delete(filename):
        safe_name = os.path.basename(filename)
        project_id = request.args.get("project_id", None, type=int)
        path = os.path.join(user_reports_dir(project_id), safe_name)
        if os.path.isfile(path):
            os.unlink(path)
        return jsonify({"ok": True})

    # ── PCAP file browser ─────────────────────────────────────

    @app.route("/api/files")
    @login_required
    def api_files_list():
        project_id = request.args.get("project_id", None, type=int)
        files = []
        udir = user_uploads_dir(project_id)
        if os.path.isdir(udir):
            for fn in os.listdir(udir):
                if not fn.lower().endswith((".pcap", ".pcapng", ".cap")):
                    continue
                path = os.path.join(udir, fn)
                try:
                    stat = os.stat(path)
                    files.append({
                        "name": fn,
                        "size": stat.st_size,
                        "modified": datetime.fromtimestamp(
                            stat.st_mtime, tz=timezone.utc
                        ).isoformat(),
                    })
                except Exception:
                    pass
        files.sort(key=lambda f: f["modified"], reverse=True)

        # Merge preset PCAPs (read-only, baked into image, nested by category)
        presets = []
        if os.path.isdir(config.PRESETS_DIR):
            for cat_name in sorted(os.listdir(config.PRESETS_DIR)):
                cat_dir = os.path.join(config.PRESETS_DIR, cat_name)
                if not os.path.isdir(cat_dir):
                    continue
                cat_files = []
                for fn in sorted(os.listdir(cat_dir)):
                    if not fn.lower().endswith((".pcap", ".pcapng", ".cap")):
                        continue
                    path = os.path.join(cat_dir, fn)
                    try:
                        stat = os.stat(path)
                        cat_files.append({
                            "name": fn,
                            "size": stat.st_size,
                            "path": f"{cat_name}/{fn}",
                        })
                    except Exception:
                        pass
                if cat_files:
                    presets.append({"category": cat_name, "files": cat_files})

        return jsonify({"files": files, "presets": presets})

    # ── PCAP upload ──────────────────────────────────────────

    @app.route("/api/upload", methods=["POST"])
    @login_required
    @limiter.limit("10 per minute")
    def api_upload():
        return _handle_upload()

    # ── Interface enumeration ────────────────────────────────

    @app.route("/api/interfaces")
    @login_required
    def api_interfaces():
        interfaces = []

        # tshark -D
        tshark_ifaces = {}
        try:
            result = subprocess.run(
                ["tshark", "-D"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    m = re.match(r"\d+\.\s+(\S+)(?:\s+\((.+)\))?", line)
                    if m:
                        tshark_ifaces[m.group(1)] = m.group(2) or ""
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # ip -j addr (Linux) or ifconfig fallback
        ip_info = {}
        try:
            result = subprocess.run(
                ["ip", "-j", "addr", "show"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                for iface in json.loads(result.stdout):
                    name = iface.get("ifname", "")
                    ips = []
                    for a in iface.get("addr_info", []):
                        if a.get("family") == "inet":
                            ips.append(a.get("local", ""))
                    ip_info[name] = {
                        "mac": iface.get("address", ""),
                        "state": iface.get("operstate", "UNKNOWN").upper(),
                        "ips": ips,
                    }
        except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError, ValueError):
            try:
                result = subprocess.run(
                    ["ifconfig"], capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0:
                    current = None
                    for line in result.stdout.split("\n"):
                        m = re.match(r"^(\S+?)[:]\s", line)
                        if m:
                            current = m.group(1)
                            ip_info[current] = {"mac": "", "state": "UP" if "UP" in line else "DOWN", "ips": []}
                        elif current:
                            m = re.search(r"(?:ether|HWaddr)\s+([0-9a-f:]{17})", line, re.I)
                            if m:
                                ip_info[current]["mac"] = m.group(1)
                            m = re.search(r"inet\s+(?:addr:)?(\d+\.\d+\.\d+\.\d+)", line)
                            if m:
                                ip_info[current]["ips"].append(m.group(1))
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        all_names = sorted(set(list(tshark_ifaces.keys()) + list(ip_info.keys())))
        for name in all_names:
            info = ip_info.get(name, {})
            state = info.get("state", "UNKNOWN")
            capturable = name in tshark_ifaces
            is_loopback = name.startswith("lo")
            suitable = capturable and state == "UP" and not is_loopback
            interfaces.append({
                "name": name,
                "state": state,
                "mac": info.get("mac", ""),
                "ips": info.get("ips", []),
                "capturable": capturable,
                "suitable": suitable,
                "description": tshark_ifaces.get(name, ""),
            })

        return jsonify({"interfaces": interfaces})

    # ── Scan history ─────────────────────────────────────────

    @app.route("/api/history")
    @login_required
    def api_scan_history():
        query = ScanHistory.query
        # Admins see all scans; regular users see only their own
        if session.get("role") != "admin":
            query = query.filter_by(user_id=session["user_id"])
        project_id = request.args.get("project_id", None, type=int)
        if project_id is not None:
            query = query.filter_by(project_id=project_id)
        limit = request.args.get("limit", 100, type=int)
        scans = query.order_by(ScanHistory.started_at.desc()).limit(limit).all()
        return jsonify({"scans": [
            {
                "run_id": s.run_id,
                "user": s.user.username if s.user else "?",
                "command": s.command,
                "pcap_source": (os.path.basename(s.pcap_source) if s.pcap_source and not s.pcap_source.startswith("live:") else s.pcap_source),
                "status": s.status,
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "completed_at": s.completed_at.isoformat() if s.completed_at else None,
                "report_filename": os.path.basename(s.report_path) if s.report_path else None,
                "node_count": s.node_count,
                "edge_count": s.edge_count,
                "error_tail": s.error_tail,
                "project_id": s.project_id,
                "project_name": s.project.name if s.project else None,
            }
            for s in scans
        ]})

    # ── System stats (admin) ────────────────────────────────

    @app.route("/system")
    @admin_required
    def system_page():
        return render_template("system.html")

    @app.route("/api/admin/stats")
    @admin_required
    def api_admin_stats():
        stats = {}

        # Uptime & platform
        try:
            with open("/proc/uptime") as f:
                uptime_secs = float(f.read().split()[0])
            stats["uptime_seconds"] = int(uptime_secs)
        except Exception:
            stats["uptime_seconds"] = None
        # platform and python version intentionally omitted

        # Memory (from /proc/meminfo)
        try:
            meminfo = {}
            with open("/proc/meminfo") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2:
                        meminfo[parts[0].rstrip(":")] = int(parts[1]) * 1024  # kB -> bytes
            stats["memory"] = {
                "total": meminfo.get("MemTotal", 0),
                "available": meminfo.get("MemAvailable", 0),
                "used": meminfo.get("MemTotal", 0) - meminfo.get("MemAvailable", 0),
            }
        except Exception:
            stats["memory"] = None

        # Disk usage for data directory
        try:
            usage = shutil.disk_usage(config.DATA_DIR)
            stats["disk"] = {
                "total": usage.total,
                "used": usage.used,
                "free": usage.free,
            }
        except Exception:
            stats["disk"] = None

        # Data directory sizes
        def dir_size(path):
            total = 0
            try:
                for dirpath, _dirnames, filenames in os.walk(path):
                    for fn in filenames:
                        try:
                            total += os.path.getsize(os.path.join(dirpath, fn))
                        except OSError:
                            pass
            except Exception:
                pass
            return total

        def file_count(path, extensions=None):
            count = 0
            try:
                for dirpath, _dirnames, filenames in os.walk(path):
                    for fn in filenames:
                        if extensions is None or any(fn.lower().endswith(e) for e in extensions):
                            count += 1
            except Exception:
                pass
            return count

        stats["data"] = {
            "uploads_size": dir_size(config.UPLOADS_DIR),
            "uploads_count": file_count(config.UPLOADS_DIR, (".pcap", ".pcapng", ".cap")),
            "reports_size": dir_size(config.REPORTS_DIR),
            "reports_count": file_count(config.REPORTS_DIR, (".json",)),
        }

        # Submissions stats
        stats["submissions"] = {
            "total_size": dir_size(config.SUBMISSIONS_DIR),
            "total_count": file_count(config.SUBMISSIONS_DIR),
        }

        # Database stats
        stats["db"] = {
            "users": User.query.count(),
            "scans_total": ScanHistory.query.count(),
            "scans_completed": ScanHistory.query.filter_by(status="completed").count(),
            "scans_failed": ScanHistory.query.filter_by(status="failed").count(),
            "scans_running": ScanHistory.query.filter_by(status="running").count(),
        }

        # Active in-memory runs
        with _runs_lock:
            active = _get_active_runs()
            stats["active_scans"] = len(active)

        # CPU load
        try:
            load1, load5, load15 = os.getloadavg()
            stats["load"] = {"1m": round(load1, 2), "5m": round(load5, 2), "15m": round(load15, 2)}
        except Exception:
            stats["load"] = None

        # CPU count
        try:
            stats["cpu_count"] = os.cpu_count()
        except Exception:
            stats["cpu_count"] = None

        # Per-user storage breakdown
        user_storage = []
        users = User.query.all()
        for u in users:
            u_uploads = os.path.join(config.UPLOADS_DIR, str(u.id))
            u_reports = os.path.join(config.REPORTS_DIR, str(u.id))
            user_storage.append({
                "username": u.username,
                "user_id": u.id,
                "uploads_size": dir_size(u_uploads),
                "uploads_count": file_count(u_uploads, (".pcap", ".pcapng", ".cap")),
                "reports_size": dir_size(u_reports),
                "reports_count": file_count(u_reports, (".json",)),
            })
        stats["user_storage"] = user_storage

        return jsonify(stats)

    # ── Admin preset (sample library) management ────────────

    _SAFE_NAME_RE = re.compile(r'^[a-zA-Z0-9._-]+$')

    def _safe_preset_name(name):
        """Validate and sanitise a preset name (category or filename)."""
        name = os.path.basename(name).strip()
        if not name or not _SAFE_NAME_RE.match(name):
            return None
        return name

    @app.route("/api/admin/presets")
    @admin_required
    def api_admin_presets_list():
        categories = []
        if os.path.isdir(config.PRESETS_DIR):
            for cat_name in sorted(os.listdir(config.PRESETS_DIR)):
                cat_dir = os.path.join(config.PRESETS_DIR, cat_name)
                if not os.path.isdir(cat_dir):
                    continue
                files = []
                total_size = 0
                for fn in sorted(os.listdir(cat_dir)):
                    path = os.path.join(cat_dir, fn)
                    if not os.path.isfile(path):
                        continue
                    try:
                        sz = os.path.getsize(path)
                    except OSError:
                        sz = 0
                    files.append({"name": fn, "size": sz})
                    total_size += sz
                categories.append({
                    "name": cat_name,
                    "files": files,
                    "file_count": len(files),
                    "total_size": total_size,
                })
        return jsonify({"categories": categories})

    @app.route("/api/admin/presets/upload", methods=["POST"])
    @admin_required
    @limiter.limit("20 per minute")
    def api_admin_presets_upload():
        if "file" not in request.files:
            return jsonify({"ok": False, "error": "No file part"}), 400
        f = request.files["file"]
        if not f.filename:
            return jsonify({"ok": False, "error": "No file selected"}), 400

        category = _safe_preset_name(request.form.get("category", ""))
        if not category:
            return jsonify({"ok": False, "error": "Invalid category name"}), 400

        safe_name = _safe_preset_name(f.filename)
        if not safe_name:
            return jsonify({"ok": False, "error": "Invalid filename (alphanumeric, dots, hyphens, underscores only)"}), 400

        # Stream to temp, validate magic bytes, enforce size limit
        cat_dir = os.path.join(config.PRESETS_DIR, category)
        os.makedirs(cat_dir, exist_ok=True)

        import tempfile
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".pcap", dir=cat_dir)
        written = 0
        magic_checked = False
        try:
            with os.fdopen(tmp_fd, "wb") as out:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    if not magic_checked:
                        if len(chunk) < 4:
                            chunk += f.read(4 - len(chunk))
                        if len(chunk) < 4 or chunk[:4] not in PCAP_MAGIC:
                            os.unlink(tmp_path)
                            return jsonify({"ok": False, "error": "Not a valid PCAP file"}), 400
                        magic_checked = True
                    written += len(chunk)
                    if written > config.PCAP_MAX_SIZE:
                        os.unlink(tmp_path)
                        return jsonify({"ok": False, "error": f"File too large (max {config.PCAP_MAX_SIZE // (1024*1024)} MB)"}), 413
                    out.write(chunk)
        except Exception:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise

        if written == 0:
            os.unlink(tmp_path)
            return jsonify({"ok": False, "error": "Empty file"}), 400

        final_path = os.path.join(cat_dir, safe_name)
        os.rename(tmp_path, final_path)
        log.info("Preset upload: %s/%s by %s (%d bytes)", category, safe_name, session.get("user", "?"), written)
        return jsonify({"ok": True, "category": category, "filename": safe_name, "size": written})

    @app.route("/api/admin/presets/category", methods=["POST"])
    @admin_required
    def api_admin_presets_create_category():
        body = request.get_json(silent=True) or {}
        name = _safe_preset_name(body.get("name", ""))
        if not name:
            return jsonify({"ok": False, "error": "Invalid category name (alphanumeric, dots, hyphens, underscores only)"}), 400
        cat_dir = os.path.join(config.PRESETS_DIR, name)
        if os.path.exists(cat_dir):
            return jsonify({"ok": False, "error": "Category already exists"}), 409
        os.makedirs(cat_dir, exist_ok=True)
        log.info("Preset category created: %s by %s", name, session.get("user", "?"))
        return jsonify({"ok": True, "name": name})

    @app.route("/api/admin/presets/category/<name>", methods=["PUT"])
    @admin_required
    def api_admin_presets_rename_category(name):
        old_name = _safe_preset_name(name)
        if not old_name:
            return jsonify({"ok": False, "error": "Invalid category name"}), 400
        body = request.get_json(silent=True) or {}
        new_name = _safe_preset_name(body.get("name", ""))
        if not new_name:
            return jsonify({"ok": False, "error": "Invalid new name"}), 400
        old_dir = os.path.join(config.PRESETS_DIR, old_name)
        new_dir = os.path.join(config.PRESETS_DIR, new_name)
        if not os.path.isdir(old_dir):
            return jsonify({"ok": False, "error": "Category not found"}), 404
        if os.path.exists(new_dir):
            return jsonify({"ok": False, "error": "Target name already exists"}), 409
        os.rename(old_dir, new_dir)
        log.info("Preset category renamed: %s -> %s by %s", old_name, new_name, session.get("user", "?"))
        return jsonify({"ok": True})

    @app.route("/api/admin/presets/<category>/<filename>", methods=["DELETE"])
    @admin_required
    def api_admin_presets_delete_file(category, filename):
        if request.args.get("confirm") != "true":
            return jsonify({"ok": False, "error": "Add ?confirm=true to delete"}), 400
        cat = _safe_preset_name(category)
        fn = _safe_preset_name(filename)
        if not cat or not fn:
            return jsonify({"ok": False, "error": "Invalid name"}), 400
        path = os.path.join(config.PRESETS_DIR, cat, fn)
        if not os.path.isfile(path):
            return jsonify({"ok": False, "error": "File not found"}), 404
        os.unlink(path)
        log.info("Preset deleted: %s/%s by %s", cat, fn, session.get("user", "?"))
        return jsonify({"ok": True})

    @app.route("/api/admin/presets/category/<name>", methods=["DELETE"])
    @admin_required
    def api_admin_presets_delete_category(name):
        if request.args.get("confirm") != "true":
            return jsonify({"ok": False, "error": "Add ?confirm=true to delete"}), 400
        cat = _safe_preset_name(name)
        if not cat:
            return jsonify({"ok": False, "error": "Invalid category name"}), 400
        cat_dir = os.path.join(config.PRESETS_DIR, cat)
        if not os.path.isdir(cat_dir):
            return jsonify({"ok": False, "error": "Category not found"}), 404
        shutil.rmtree(cat_dir)
        log.info("Preset category deleted: %s by %s", cat, session.get("user", "?"))
        return jsonify({"ok": True})

    # ── User management (admin) ──────────────────────────────

    @app.route("/users")
    @admin_required
    def users_page():
        return render_template("users.html")

    @app.route("/api/users")
    @admin_required
    def api_users_list():
        users = User.query.order_by(User.created_at).all()
        return jsonify({"users": [
            {
                "id": u.id,
                "username": u.username,
                "role": u.role,
                "created_at": u.created_at.isoformat() if u.created_at else None,
                "subscription_tier": u.subscription_tier or "free",
                "upload_limit_mb": u.upload_limit_mb if u.upload_limit_mb else 200,
            }
            for u in users
        ]})

    @app.route("/api/users", methods=["POST"])
    @admin_required
    @limiter.limit("3 per minute")
    def api_users_create():
        body = request.get_json(silent=True) or {}
        username = body.get("username", "").strip()
        password = body.get("password", "")
        role = body.get("role", "user")
        if not username or not password:
            return jsonify({"ok": False, "error": "Username and password required"}), 400
        if len(password) < 8:
            return jsonify({"ok": False, "error": "Password must be at least 8 characters"}), 400
        if role not in ("admin", "user"):
            return jsonify({"ok": False, "error": "Invalid role"}), 400
        if User.query.filter_by(username=username).first():
            return jsonify({"ok": False, "error": "Username already exists"}), 409
        create_user(username, password, role)
        log.info("User created: %s (role=%s) by %s", username, role, session.get("user", "?"))
        return jsonify({"ok": True})

    @app.route("/api/users/<username>", methods=["DELETE"])
    @admin_required
    def api_users_delete(username):
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({"ok": False, "error": "User not found"}), 404
        if user.username == session.get("user"):
            return jsonify({"ok": False, "error": "Cannot delete yourself"}), 400
        log.info("User deleted: %s by %s", username, session.get("user", "?"))
        db.session.delete(user)
        db.session.commit()
        return jsonify({"ok": True})

    @app.route("/api/users/<username>/password", methods=["POST"])
    @admin_required
    def api_users_change_password(username):
        body = request.get_json(silent=True) or {}
        new_pass = body.get("password", "")
        if not new_pass:
            return jsonify({"ok": False, "error": "Password required"}), 400
        if len(new_pass) < 8:
            return jsonify({"ok": False, "error": "Password must be at least 8 characters"}), 400
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({"ok": False, "error": "User not found"}), 404
        change_password(user, new_pass)
        return jsonify({"ok": True})

    @app.route("/api/account/password", methods=["POST"])
    @login_required
    def api_account_change_password():
        body = request.get_json(silent=True) or {}
        current = body.get("current_password", "")
        new_pass = body.get("new_password", "")
        if not current or not new_pass:
            return jsonify({"ok": False, "error": "Current and new password required"}), 400
        if len(new_pass) < 8:
            return jsonify({"ok": False, "error": "Password must be at least 8 characters"}), 400
        user = User.query.filter_by(username=session["user"]).first()
        if not verify_user(user.username, current):
            return jsonify({"ok": False, "error": "Current password is incorrect"}), 403
        change_password(user, new_pass)
        return jsonify({"ok": True})

    # ── Profile ───────────────────────────────────────────────

    @app.route("/profile")
    @login_required
    def profile_page():
        return render_template("profile.html")

    @app.route("/api/profile", methods=["GET"])
    @login_required
    def api_profile_get():
        user = User.query.get(session["user_id"])
        scan_count = ScanHistory.query.filter_by(user_id=user.id).count()
        project_count = Project.query.filter_by(user_id=user.id).count()
        return jsonify({
            "username": user.username,
            "role": user.role,
            "email": user.email or "",
            "full_name": user.full_name or "",
            "company": user.company or "",
            "phone": user.phone or "",
            "birthday": user.birthday.isoformat() if user.birthday else "",
            "address": user.address or "",
            "subscription_tier": user.subscription_tier or "free",
            "upload_limit_mb": user.upload_limit_mb if user.upload_limit_mb else 200,
            "joined": user.created_at.isoformat() if user.created_at else "",
            "scan_count": scan_count,
            "project_count": project_count,
        })

    @app.route("/api/profile", methods=["POST"])
    @login_required
    def api_profile_update():
        body = request.get_json(silent=True) or {}
        user = User.query.get(session["user_id"])
        for field in ("full_name", "company", "phone", "address"):
            if field in body:
                val = body[field].strip() if body[field] else None
                setattr(user, field, val or None)
        if "email" in body:
            email_val = body["email"].strip() if body["email"] else None
            if email_val and User.query.filter(User.email == email_val, User.id != user.id).first():
                return jsonify({"ok": False, "error": "Email already in use"}), 409
            user.email = email_val or None
        if "birthday" in body:
            try:
                from datetime import date as _date
                user.birthday = _date.fromisoformat(body["birthday"]) if body["birthday"] else None
            except ValueError:
                return jsonify({"ok": False, "error": "Invalid birthday format (YYYY-MM-DD)"}), 400
        db.session.commit()
        return jsonify({"ok": True})

    @app.route("/api/users/<username>/limits", methods=["POST"])
    @admin_required
    def api_users_set_limits(username):
        body = request.get_json(silent=True) or {}
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({"ok": False, "error": "User not found"}), 404
        if "subscription_tier" in body:
            tier = body["subscription_tier"]
            if tier not in ("free", "pro", "enterprise"):
                return jsonify({"ok": False, "error": "Invalid tier"}), 400
            user.subscription_tier = tier
        if "upload_limit_mb" in body:
            try:
                limit = int(body["upload_limit_mb"])
                if limit < 1 or limit > 10000:
                    raise ValueError
                user.upload_limit_mb = limit
            except (ValueError, TypeError):
                return jsonify({"ok": False, "error": "upload_limit_mb must be 1–10000"}), 400
        db.session.commit()
        log.info("Limits updated for %s by %s: %s", username, session.get("user", "?"), body)
        return jsonify({"ok": True})

    return app


# ═══════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app = create_app()
    print(f"[marlinspike] Starting on http://{config.HOST}:{config.PORT}")
    app.run(host=config.HOST, port=config.PORT, debug=False)
