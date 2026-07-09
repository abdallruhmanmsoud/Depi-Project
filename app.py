"""
Forensics Dashboard — main Flask application.

Run with:
    python app.py
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timezone

from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename

import config
from utils.loader import discover_tools
from utils.reporter import save_report, save_json_report
from utils.validator import validate_upload
from utils.pipeline_dispatcher import run as dispatch_pipeline

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(level=config.LOG_LEVEL, format=config.LOG_FORMAT)
logger = logging.getLogger("dashboard")

# ---------------------------------------------------------------------------
# Flask + SocketIO setup
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = config.SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = config.MAX_CONTENT_LENGTH

socketio = SocketIO(app, async_mode="gevent", cors_allowed_origins="*")

# ---------------------------------------------------------------------------
# Ensure directories exist
# ---------------------------------------------------------------------------
os.makedirs(config.UPLOAD_FOLDER, exist_ok=True)
os.makedirs(config.REPORT_FOLDER, exist_ok=True)

# ---------------------------------------------------------------------------
# Discover tools
# ---------------------------------------------------------------------------
TOOLS: dict = discover_tools(config.TOOLS_FOLDER)

# In‑memory store for analysis sessions
# session_id → {"tool_id", "filename", "filepath", "logs": [], "status", "report_path"}
SESSIONS: dict[str, dict] = {}

# ---------------------------------------------------------------------------
# Category definitions – maps each AI‑pipeline category to its tool IDs.
# Tool IDs come from the existing discover_tools() mechanism.
# ---------------------------------------------------------------------------
CATEGORY_DEFS = {
    "memory": {
        "name": "Memory",
        "subtitle": "Memory Forensics",
        "icon": "bi-cpu",
        "color": "#8b5cf6",
        "tool_ids": ["volatility", "vol_runner"],
    },
    "database": {
        "name": "Database",
        "subtitle": "Database Auditing",
        "icon": "bi-database",
        "color": "#06b6d4",
        "tool_ids": ["mysqlbinlog", "percona", "pgaudit"],
    },
    "disk": {
        "name": "Disk",
        "subtitle": "Disk Forensics",
        "icon": "bi-hdd-stack",
        "color": "#f59e0b",
        "tool_ids": ["dc3dd", "ewfacquire", "fls", "tsk", "bulk_extractor"],
    },
    "browser": {
        "name": "Browser",
        "subtitle": "Browser Artifacts",
        "icon": "bi-globe2",
        "color": "#10b981",
        "tool_ids": ["browserhistoryview", "bft", "browserpwdview", "chromecacheview", "hindsight"],
    },
    "malware": {
        "name": "Malware",
        "subtitle": "Malware Analysis",
        "icon": "bi-bug",
        "color": "#ef4444",
        "tool_ids": ["pestudio", "die", "floss", "exeinfope", "resourcehacker", "rlpack"],
    },
    "network": {
        "name": "Network",
        "subtitle": "Network Traffic",
        "icon": "bi-diagram-3",
        "color": "#3b82f6",
        "tool_ids": ["tshark", "zeek", "tcpflow"],
    },
}


def _build_tool_info(tid: str, tcls) -> dict:
    """Build a tool‑info dict from a discovered tool class."""
    prereqs = tcls.check_prerequisites()
    return {
        "tool_id": tid,
        "name": tcls.name,
        "description": tcls.description,
        "accepted_extensions": getattr(tcls, "accepted_extensions", []),
        "prerequisites": prereqs,
        "all_ok": all(p.get("installed", False) for p in prereqs),
    }


def _get_tool_category(tool_id: str):
    """Return (category_id, category_dict) for a tool, or (None, None)."""
    for cat_id, cat in CATEGORY_DEFS.items():
        if tool_id in cat["tool_ids"]:
            return cat_id, cat
    return None, None


def _categorized_tools():
    """Return (categories_list, utility_tools_list) from discovered TOOLS."""
    categorized_ids: set[str] = set()
    categories = []
    for cat_id, cat in CATEGORY_DEFS.items():
        tools_in_cat = []
        for tid in cat["tool_ids"]:
            if tid in TOOLS:
                tools_in_cat.append(_build_tool_info(tid, TOOLS[tid]))
                categorized_ids.add(tid)
        categories.append({
            "category_id": cat_id,
            "name": cat["name"],
            "subtitle": cat["subtitle"],
            "icon": cat["icon"],
            "color": cat["color"],
            "tool_count": len(tools_in_cat),
            "tools": tools_in_cat,
        })
    # Any discovered tool not in a category goes to Utilities
    utilities = []
    for tid, tcls in TOOLS.items():
        if tid not in categorized_ids:
            utilities.append(_build_tool_info(tid, tcls))
    return categories, utilities


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.route("/")
def index():
    """Dashboard home – shows forensic categories."""
    categories, utilities = _categorized_tools()
    return render_template("index.html", categories=categories, utilities=utilities)


@app.route("/tool/<tool_id>")
def tool_page(tool_id: str):
    """Dedicated page for a single tool."""
    if tool_id not in TOOLS:
        flash(f"Unknown tool: {tool_id}", "danger")
        return redirect(url_for("index"))
    tcls = TOOLS[tool_id]
    prereqs = tcls.check_prerequisites()
    cat_id, cat_info = _get_tool_category(tool_id)
    return render_template(
        "tool.html",
        tool_id=tool_id,
        tool_name=tcls.name,
        tool_description=tcls.description,
        accepted_extensions=tcls.accepted_extensions,
        prerequisites=prereqs,
        all_ok=all(p["installed"] for p in prereqs),
        category_id=cat_id,
        category=cat_info,
    )


@app.route("/category/<category_id>")
def category_page(category_id: str):
    """Shows tools belonging to a forensic category."""
    if category_id not in CATEGORY_DEFS:
        flash(f"Unknown category: {category_id}", "danger")
        return redirect(url_for("index"))
    cat = CATEGORY_DEFS[category_id]
    tool_infos = []
    for tid in cat["tool_ids"]:
        if tid in TOOLS:
            tool_infos.append(_build_tool_info(tid, TOOLS[tid]))
    return render_template(
        "category.html",
        category_id=category_id,
        category=cat,
        tools=tool_infos,
    )


@app.route("/upload/<tool_id>", methods=["POST"])
def upload(tool_id: str):
    """Handle file upload and return a session id."""
    if tool_id not in TOOLS:
        return jsonify({"error": f"Unknown tool: {tool_id}"}), 404

    if "file" not in request.files:
        return jsonify({"error": "No file part in request"}), 400

    file = request.files["file"]
    if not file or file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    filename = secure_filename(file.filename)
    session_id = uuid.uuid4().hex[:12]
    dest_dir = os.path.join(config.UPLOAD_FOLDER, session_id)
    os.makedirs(dest_dir, exist_ok=True)
    filepath = os.path.join(dest_dir, filename)
    file.save(filepath)

    # Validate
    tcls = TOOLS[tool_id]
    ok, msg = validate_upload(filepath, tcls.accepted_extensions)
    if not ok:
        return jsonify({"error": msg}), 400

    SESSIONS[session_id] = {
        "tool_id": tool_id,
        "filename": filename,
        "filepath": filepath,
        "logs": [f"File uploaded: {filename}", f"Validation: {msg}"],
        "status": "ready",
        "report_path": None,
    }

    logger.info("Upload OK — session=%s tool=%s file=%s", session_id, tool_id, filename)
    return jsonify({"session_id": session_id, "message": msg})


@app.route("/local/<tool_id>", methods=["POST"])
def use_local_file(tool_id: str):
    """Use a local file path instead of uploading (for large files)."""
    if tool_id not in TOOLS:
        return jsonify({"error": f"Unknown tool: {tool_id}"}), 404

    data = request.get_json(silent=True) or {}
    filepath = data.get("filepath", "").strip()
    if not filepath:
        return jsonify({"error": "No file path provided."}), 400

    if not os.path.isabs(filepath):
        return jsonify({"error": "Please provide an absolute file path."}), 400

    if not os.path.isfile(filepath):
        return jsonify({"error": f"File not found: {filepath}"}), 404

    filename = os.path.basename(filepath)
    tcls = TOOLS[tool_id]
    ok, msg = validate_upload(filepath, tcls.accepted_extensions)
    if not ok:
        return jsonify({"error": msg}), 400

    session_id = uuid.uuid4().hex[:12]
    SESSIONS[session_id] = {
        "tool_id": tool_id,
        "filename": filename,
        "filepath": filepath,
        "logs": [f"Local file: {filepath}", f"Validation: {msg}"],
        "status": "ready",
        "report_path": None,
    }

    logger.info("Local file OK — session=%s tool=%s file=%s", session_id, tool_id, filepath)
    return jsonify({"session_id": session_id, "message": msg})


@app.route("/session/<session_id>")
def session_page(session_id: str):
    """View an analysis session with live logs."""
    sess = SESSIONS.get(session_id)
    if not sess:
        flash("Session not found.", "danger")
        return redirect(url_for("index"))
    tcls = TOOLS.get(sess["tool_id"])
    tool_name = tcls.name if tcls else sess["tool_id"]
    return render_template(
        "session.html",
        session_id=session_id,
        sess=sess,
        tool_name=tool_name,
    )


@app.route("/report/<session_id>")
def download_report(session_id: str):
    """Download the saved report for a session."""
    sess = SESSIONS.get(session_id)
    if not sess or not sess.get("report_path"):
        flash("No report available.", "warning")
        return redirect(url_for("index"))
    return send_file(sess["report_path"], as_attachment=True)


@app.route("/report/json/<session_id>")
def download_json_report(session_id: str):
    """Download the saved JSON report for a session."""
    sess = SESSIONS.get(session_id)
    if not sess or not sess.get("report_path_json"):
        flash("No JSON report available.", "warning")
        return redirect(url_for("index"))
    return send_file(sess["report_path_json"], as_attachment=True, mimetype="application/json")


@app.route("/api/tools")
def api_tools():
    """JSON list of available tools and their prerequisite status."""
    data = []
    for tid, tcls in TOOLS.items():
        prereqs = tcls.check_prerequisites()
        data.append({
            "tool_id": tid,
            "name": tcls.name,
            "description": tcls.description,
            "accepted_extensions": tcls.accepted_extensions,
            "prerequisites": prereqs,
            "all_ok": all(p["installed"] for p in prereqs),
        })
    return jsonify(data)


@app.route("/api/categories")
def api_categories():
    """JSON list of forensic categories with their tools."""
    categories, utilities = _categorized_tools()
    return jsonify({"categories": categories, "utilities": utilities})


@app.route("/api/sessions")
def api_sessions():
    """JSON list of recent sessions."""
    return jsonify({
        sid: {
            "tool_id": s["tool_id"],
            "filename": s["filename"],
            "status": s["status"],
        }
        for sid, s in SESSIONS.items()
    })


# ---------------------------------------------------------------------------
# WebSocket events
# ---------------------------------------------------------------------------


@socketio.on("run_analysis")
def handle_run_analysis(data):
    """Client sends ``{session_id}`` to kick off tool execution.

    Flow:
        1. Run tool_instance.run() to collect raw CLI output.
        2. Call dispatch_pipeline() which routes to the category's
           existing AI pipeline (normaliser → model → MITRE → report).
        3. Store the enriched AI result on the session.
        4. Save raw text/JSON reports via utils/reporter for backwards compat.
    """
    session_id = data.get("session_id", "")
    sess = SESSIONS.get(session_id)
    if not sess:
        emit("log", {"line": "ERROR: session not found.", "done": True})
        return

    if sess["status"] == "running":
        emit("log", {"line": "Analysis is already running.", "done": False})
        return

    tool_id = sess["tool_id"]
    tcls = TOOLS.get(tool_id)
    if not tcls:
        emit("log", {"line": f"ERROR: tool '{tool_id}' not found.", "done": True})
        return

    sess["status"] = "running"
    sess["logs"].append(f"--- Analysis started at {datetime.now(timezone.utc).isoformat()} ---")
    emit("log", {"line": f"Starting {tcls.name} analysis ...", "done": False})

    # sid captured here so stream() can safely reference it inside the gevent thread
    _sid = request.sid

    def stream(line: str):
        sess["logs"].append(line)
        socketio.emit("log", {"line": line, "done": False}, to=_sid)

    # ── Stage 1: Raw tool execution ───────────────────────────────────────────
    raw_output_parts: list[str] = []

    def capturing_stream(line: str):
        raw_output_parts.append(line)
        stream(line)

    try:
        stream("[Stage 1/7] Running tool ...")
        tool_instance = tcls()
        results = tool_instance.run(sess["filepath"], emit=capturing_stream)
        sess["results"] = [
            {
                "command": r.command,
                "output":  r.output,
                "return_code": r.return_code,
                "success": r.success,
            }
            for r in results
        ]
        stream(f"[Stage 1/7] Tool finished — {len(results)} command(s) executed.")
    except Exception as exc:
        sess["status"] = "error"
        stream(f"FATAL ERROR during tool execution: {exc}")
        logger.exception("Tool execution failed for session %s", session_id)
        emit("log", {"line": "--- Analysis finished (tool error) ---", "done": True})
        return

    # Combine all raw output for the pipeline
    raw_tool_output = "\n".join(raw_output_parts)

    # ── Stage 2–7: AI Pipeline (normalise → features → model → MITRE → report) ─
    cat_id, _cat_info = _get_tool_category(tool_id)
    pipeline_output_dir = os.path.join(config.REPORT_FOLDER, "pipeline", session_id)

    stream("[Stage 2/7] Parsing & normalising output ...")
    stream("[Stage 3/7] Extracting features ...")
    stream("[Stage 4/7] Loading AI model ...")

    ai_result: dict = {}
    if cat_id:
        stream(f"[Pipeline] Dispatching to {cat_id} pipeline ...")
        try:
            ai_result = dispatch_pipeline(
                category=cat_id,
                tool_id=tool_id,
                filepath=sess["filepath"],
                raw_tool_output=raw_tool_output,
                session_id=session_id,
                output_dir=pipeline_output_dir,
                emit=stream,
            )
        except Exception as exc:
            stream(f"[Pipeline ERROR] Unhandled dispatcher failure: {exc}")
            logger.exception("Pipeline dispatcher crashed — session=%s", session_id)
            ai_result = {"stage": "error", "error": {"reason": str(exc)}}
    else:
        stream(f"[Pipeline] Tool '{tool_id}' has no AI category — skipping AI pipeline.")
        ai_result = {"stage": "skipped"}

    # ── Store enriched AI result on session ───────────────────────────────────
    sess["ai_result"] = ai_result

    if ai_result.get("stage") == "complete":
        stream("[Stage 5/7] Running prediction ... done.")
        stream("[Stage 6/7] Running MITRE mapping ... done.")
        stream("[Stage 7/7] Generating digital forensics report ... done.")
        stream(
            f"[Pipeline] Prediction={ai_result.get('prediction')}  "
            f"risk={ai_result.get('risk_level')}  "
            f"techniques={len(ai_result.get('mitre_techniques', []))}"
        )
        # Prefer the richer AI-generated HTML report as the primary download
        if ai_result.get("report_html_location"):
            sess["report_path"] = ai_result["report_html_location"]
        if ai_result.get("report_json_location"):
            sess["report_path_json"] = ai_result["report_json_location"]
    elif ai_result.get("error"):
        err = ai_result["error"]
        stream(f"[Pipeline WARN] Pipeline stage '{err.get('stage')}' failed: {err.get('reason')}")

    # ── Always save a raw text/JSON report for backwards compatibility ─────────
    try:
        raw_report_path = save_report(
            config.REPORT_FOLDER, tool_id, sess["filename"], sess["logs"]
        )
        raw_json_path = save_json_report(
            config.REPORT_FOLDER, tool_id, sess["filename"],
            sess["logs"], sess["results"],
        )
        # Only fall back to raw reports if the AI pipeline didn't produce one
        if not sess.get("report_path"):
            sess["report_path"] = raw_report_path
        if not sess.get("report_path_json"):
            sess["report_path_json"] = raw_json_path
        stream(f"Raw report saved: {os.path.basename(raw_report_path)}")
    except Exception as exc:
        stream(f"[WARN] Raw report save failed: {exc}")

    sess["status"] = "complete"

    emit("log", {
        "line": "--- Analysis finished ---",
        "done": True,
        "results": sess.get("results"),
        "ai_result": {
            "prediction":       ai_result.get("prediction"),
            "risk_level":       ai_result.get("risk_level"),
            "anomaly_score":    ai_result.get("anomaly_score"),
            "confidence":       ai_result.get("confidence"),
            "mitre_techniques": ai_result.get("mitre_techniques", []),
            "recommendations":  ai_result.get("recommendations", []),
            "stage":            ai_result.get("stage"),
        },
    })


@socketio.on("save_report")
def handle_save_report(data):
    """Manually trigger report saving."""
    session_id = data.get("session_id", "")
    sess = SESSIONS.get(session_id)
    if not sess:
        emit("report_saved", {"error": "Session not found."})
        return
    report_path = save_report(
        config.REPORT_FOLDER,
        sess["tool_id"],
        sess["filename"],
        sess["logs"],
    )
    sess["report_path"] = report_path

    report_path_json = save_json_report(
        config.REPORT_FOLDER,
        sess["tool_id"],
        sess["filename"],
        sess["logs"],
        sess.get("results"),
    )
    sess["report_path_json"] = report_path_json

    emit("report_saved", {
        "path": report_path,
        "name": os.path.basename(report_path),
        "path_json": report_path_json,
        "name_json": os.path.basename(report_path_json)
    })


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logger.info("Discovered %d tool(s): %s", len(TOOLS), ", ".join(TOOLS.keys()))
    print(">>> STARTING SERVER <<<")

    socketio.run(
        app,
        host="0.0.0.0",
        port=5000,
        debug=False,
        use_reloader=False
    )
