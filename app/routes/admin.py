import json
from datetime import timedelta
# pyrefly: ignore [missing-import]
from flask import Blueprint, request, redirect, url_for, render_template, session, make_response, jsonify

from models import get_db
from services.siem import (
    send_log,
    query_attack_counters, query_events_timeline, query_top_ips,
    query_attack_reasons, query_recent_events
)
from services.ai_analysis import (
    get_recent_logs, build_security_summary, analyze_with_ollama,
    save_ai_alert, latest_ai_alert, format_ai_result_for_alert
)
from services.rate_limiter import parse_dt, now_local
from services.dos_protection import get_dos_stats
from services.session_manager import (
    is_admin_logged_in, get_admin_session, admin_username, admin_role
)

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


def login_required():
    return is_admin_logged_in()


def role_required(role):
    return admin_role() == role


def deny_access(requested_path, reason):
    if reason == "not_logged_in":
        return redirect(url_for("auth.login", expired="idle"))
        
    admin_sess = get_admin_session()
    user = admin_sess["username"] if admin_sess else "anonymous"
    role = admin_sess["role"] if admin_sess else "unknown"
    send_log("access_denied", user, role, False, reason, {"requested_path": requested_path})
    html = render_template(
        "access_denied.html",
        path=requested_path,
        role=role,
        user=user,
        logged_in=login_required()
    )
    return make_response(html, 403)


# ========= Admin Dashboard =========
@admin_bp.route("/")
def admin_page():
    if not login_required():
        return deny_access("/admin", "not_logged_in")
    if not role_required("admin"):
        return deny_access("/admin", "role_not_allowed")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    total_users = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM users WHERE is_active = 1")
    active_users = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM users WHERE is_active = 0")
    pending_users = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM ai_alerts")
    alert_count = cur.fetchone()[0]
    conn.close()

    alert = latest_ai_alert()
    return render_template(
        "admin_dashboard.html",
        username=admin_username(),
        role=admin_role(),
        latest_alert=alert,
        total_users=total_users,
        active_users=active_users,
        pending_users=pending_users,
        alert_count=alert_count
    )


# ========= SIEM Dashboard (Embedded OpenSearch) =========
@admin_bp.route("/siem")
def admin_siem():
    if not login_required():
        return deny_access("/admin/siem", "not_logged_in")
    if not role_required("admin"):
        return deny_access("/admin/siem", "role_not_allowed")

    send_log("admin_view_siem", admin_username() or "admin", "admin", True, "ok")
    return render_template("admin_siem.html")


# ========= SIEM API Endpoints (for Chart.js) =========
@admin_bp.route("/api/siem-stats")
def api_siem_stats():
    if not login_required() or not role_required("admin"):
        return jsonify({"error": "unauthorized"}), 403

    counters = query_attack_counters()
    timeline = query_events_timeline(days=30)
    top_ips = query_top_ips(size=10)
    reasons = query_attack_reasons(size=15)
    dos_stats = get_dos_stats()

    return jsonify({
        "ok": True,
        "counters": counters,
        "timeline": timeline,
        "top_ips": top_ips,
        "reasons": reasons,
        "dos_realtime": dos_stats
    })


@admin_bp.route("/api/siem-logs")
def api_siem_logs():
    if not login_required() or not role_required("admin"):
        return jsonify({"error": "unauthorized"}), 403

    events = query_recent_events(limit=25)
    return jsonify({"ok": True, "events": events})


# ========= User Management =========
@admin_bp.route("/users")
def admin_users():
    if not login_required():
        return deny_access("/admin/users", "not_logged_in")
    if not role_required("admin"):
        return deny_access("/admin/users", "role_not_allowed")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, username, email, role, is_active FROM users ORDER BY id ASC")
    users = cur.fetchall()
    conn.close()

    send_log("admin_view_users", admin_username() or "admin", "admin", True, "ok", {"count": len(users)})
    return render_template("admin_users.html", users=users, msg=None, ok=True)


@admin_bp.route("/users/<int:user_id>/toggle", methods=["POST"])
def admin_toggle_user(user_id):
    if not login_required():
        return deny_access(f"/admin/users/{user_id}/toggle", "not_logged_in")
    if not role_required("admin"):
        return deny_access(f"/admin/users/{user_id}/toggle", "role_not_allowed")

    action = request.form.get("action", "").strip().lower()
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()

    if not user:
        conn.close()
        return make_response("User not found", 404)

    if user["username"] == "admin":
        conn.close()
        return redirect(url_for("admin.admin_users"))

    if action == "enable":
        cur.execute("UPDATE users SET is_active = 1 WHERE id = ?", (user_id,))
        conn.commit()
        send_log("admin_account_enabled", admin_username() or "admin", "admin", True, "account_enabled", {
            "target_user": user["username"]
        })
    elif action == "disable":
        cur.execute("UPDATE users SET is_active = 0 WHERE id = ?", (user_id,))
        conn.commit()
        send_log("admin_account_disabled", admin_username() or "admin", "admin", True, "account_disabled", {
            "target_user": user["username"]
        })

    conn.close()
    return redirect(url_for("admin.admin_users"))


@admin_bp.route("/users/<int:user_id>/role", methods=["POST"])
def admin_change_role(user_id):
    if not login_required():
        return deny_access(f"/admin/users/{user_id}/role", "not_logged_in")
    if not role_required("admin"):
        return deny_access(f"/admin/users/{user_id}/role", "role_not_allowed")

    new_role = request.form.get("new_role", "student").strip().lower()
    if new_role not in ("student", "teacher"):
        new_role = "student"

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()

    if not user:
        conn.close()
        return make_response("User not found", 404)

    if user["username"] != "admin":
        old_role = user["role"]
        cur.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
        conn.commit()
        send_log("admin_role_changed", admin_username() or "admin", "admin", True, "role_changed", {
            "target_user": user["username"],
            "old_role": old_role,
            "new_role": new_role
        })

    conn.close()
    return redirect(url_for("admin.admin_users"))


# ========= AI Analysis =========
@admin_bp.route("/ai-analysis")
def ai_analysis():
    if not login_required():
        return deny_access("/admin/ai-analysis", "not_logged_in")
    if not role_required("admin"):
        return deny_access("/admin/ai-analysis", "role_not_allowed")

    try:
        logs = get_recent_logs()
        summary = build_security_summary(logs)
        result, raw = analyze_with_ollama(summary)

        output = {
            "security_summary": summary,
            "ai_result": result
        }

        send_log("ai_analysis_run", admin_username() or "admin", "admin", True, "ok", {"log_count": len(logs)})
        return render_template("ai_analysis.html", result=json.dumps(output, indent=2))

    except Exception as e:
        send_log("ai_analysis_failed", admin_username() or "admin", "admin", False,
                 "ollama_or_query_error", {"error": str(e)})
        return render_template("ai_analysis.html", result=f"AI analysis failed:\n\n{str(e)}")


# ========= AI Alerts =========
@admin_bp.route("/ai-alerts")
def admin_ai_alerts():
    if not login_required():
        return deny_access("/admin/ai-alerts", "not_logged_in")
    if not role_required("admin"):
        return deny_access("/admin/ai-alerts", "role_not_allowed")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM ai_alerts ORDER BY id DESC LIMIT 50")
    alerts = cur.fetchall()
    conn.close()

    return render_template("admin_ai_alerts.html", alerts=alerts)


@admin_bp.route("/ai-alerts/check")
def admin_ai_alerts_check():
    if not login_required():
        return jsonify({"ok": False})
    if not role_required("admin"):
        return jsonify({"ok": False})

    try:
        logs = get_recent_logs()
        summary = build_security_summary(logs)

        should_run_ai = (
            summary.get("failed_logins", 0) >= 3 or
            summary.get("registrations", 0) >= 3 or
            summary.get("locked_login_ips", 0) >= 1 or
            summary.get("locked_registration_ips", 0) >= 1 or
            summary.get("dos_warnings", 0) >= 1 or
            summary.get("dos_detected", 0) >= 1 or
            len(summary.get("attack_indicators", [])) >= 1
        )

        if not should_run_ai:
            return jsonify({"ok": True, "alert": None})

        result, raw = analyze_with_ollama(summary)

        if result.get("suspicious") is True:
            title, severity, summary_text = format_ai_result_for_alert(result)

            if title:
                last = latest_ai_alert()
                should_insert = True
                if last:
                    same_title = last["title"] == title
                    same_summary = last["summary"] == summary_text
                    recent_last = parse_dt(last["created_at"])
                    if same_title and same_summary and recent_last and now_local() - recent_last < timedelta(minutes=5):
                        should_insert = False

                if should_insert:
                    save_ai_alert(title, severity, summary_text, raw)
                    # Removed send_log for ai_alert_generated to prevent log clutter

            latest = latest_ai_alert()
            if latest:
                return jsonify({
                    "ok": True,
                    "alert": {
                        "title": latest["title"],
                        "severity": latest["severity"],
                        "summary": latest["summary"],
                        "created_at": latest["created_at"]
                    }
                })

        return jsonify({"ok": True, "alert": None})

    except Exception as e:
        send_log("ai_live_check_failed", admin_username() or "admin", "admin", False,
                 "ai_live_check_error", {"error": str(e)})
        return jsonify({"ok": False, "error": str(e)})
