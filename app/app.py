"""
University Portal — Main Application
=====================================
Configures Flask with security middleware:
  - DoS protection (request rate tracking per IP)
  - Session timeout management (idle + absolute)
  - HTTP security headers (OWASP best practices)
"""

from flask import Flask, abort, redirect, url_for, session, request, make_response
from datetime import timedelta

from config import (
    SECRET_KEY, SESSION_IDLE_MINUTES, SESSION_ABSOLUTE_HOURS,
    DOS_WARNING_THRESHOLD, DOS_BLOCK_THRESHOLD, DOS_WINDOW_SECONDS, DOS_BLOCK_MINUTES,
    SECURITY_HEADERS_ENABLED, SESSION_COOKIE_SECURE, FLASK_DEBUG, validate_security_config
)
from models import init_db_and_seed_admin
from services.csrf import get_csrf_token, validate_csrf_token
from services.siem import get_client_ip, send_log
from services.rate_limiter import now_local, parse_dt
from services.dos_protection import record_request as dos_record

from routes.auth import auth_bp
from routes.admin import admin_bp
from routes.teacher import teacher_bp
from routes.student import student_bp


def create_app():
    validate_security_config()

    app = Flask(__name__)
    app.config["SECRET_KEY"] = SECRET_KEY
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = SESSION_COOKIE_SECURE
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=SESSION_ABSOLUTE_HOURS)

    init_db_and_seed_admin()

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(teacher_bp)
    app.register_blueprint(student_bp)

    # Root redirect
    @app.route("/")
    def index():
        return redirect(url_for("auth.login"))

    @app.context_processor
    def inject_csrf_token():
        return {"csrf_token": get_csrf_token}

    # DoS protection runs first so request floods are blocked early.
    @app.before_request
    def check_dos():
        # Skip static files
        if request.path.startswith("/static"):
            return

        ip = get_client_ip()
        status, count = dos_record(
            ip, DOS_WINDOW_SECONDS, DOS_WARNING_THRESHOLD,
            DOS_BLOCK_THRESHOLD, DOS_BLOCK_MINUTES
        )

        if status == "blocked_existing":
            send_log("dos_ip_blocked", "unknown", "unknown", False, "dos_blocked", {
                "blocked_ip": ip
            })
            return make_response(
                "<h1>429 Too Many Requests</h1>"
                "<p>Your IP has been temporarily blocked due to excessive requests. "
                "Please try again later.</p>", 429
            )

        if status == "blocked_new":
            send_log("dos_detected", "unknown", "unknown", False, "dos_threshold_exceeded", {
                "blocked_ip": ip,
                "request_count": count,
                "block_minutes": DOS_BLOCK_MINUTES
            })
            return make_response(
                "<h1>429 Too Many Requests</h1>"
                "<p>Your IP has been temporarily blocked due to excessive requests. "
                "Please try again later.</p>", 429
            )

        if status == "warning":
            send_log("dos_warning", "unknown", "unknown", False, "dos_warning_threshold", {
                "ip": ip,
                "request_count": count,
                "threshold": DOS_WARNING_THRESHOLD
            })

        if status == "block_expired":
            send_log("dos_block_expired", ip, "unknown", True, "dos_block_expired", {
                "ip": ip
            })

    @app.before_request
    def check_csrf():
        if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
            return

        submitted_token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
        if validate_csrf_token(submitted_token):
            return

        send_log("csrf_failed", "unknown", "unknown", False, "invalid_csrf_token", {
            "request_path": request.path
        })
        abort(400, description="Invalid or missing CSRF token.")

    # Session timeout management
    @app.before_request
    def check_session_timeout():
        from services.session_manager import ADMIN_PREFIX, USER_PREFIX, get_session_by_prefix, clear_session

        # Check timeout for both session slots independently
        for prefix, role_type in [(ADMIN_PREFIX, "admin"), (USER_PREFIX, "user")]:
            sess = get_session_by_prefix(prefix)
            if not sess:
                continue

            now = now_local()

            # Check idle timeout
            last_active_str = sess.get("last_active")
            if last_active_str:
                last_active = parse_dt(last_active_str)
                if last_active and (now - last_active) > timedelta(minutes=SESSION_IDLE_MINUTES):
                    username = sess.get("username", "unknown")
                    role = sess.get("role", "unknown")
                    idle_minutes = (now - last_active).total_seconds() / 60
                    send_log("session_expired_idle", username, role, False, "idle_timeout", {
                        "idle_minutes": round(idle_minutes, 1)
                    })
                    clear_session(role_type)
                    continue

            # Check absolute timeout
            session_start_str = sess.get("session_start")
            if session_start_str:
                session_start = parse_dt(session_start_str)
                if session_start and (now - session_start) > timedelta(hours=SESSION_ABSOLUTE_HOURS):
                    username = sess.get("username", "unknown")
                    role = sess.get("role", "unknown")
                    duration_hours = (now - session_start).total_seconds() / 3600
                    send_log("session_expired_absolute", username, role, False, "absolute_timeout", {
                        "session_hours": round(duration_hours, 2)
                    })
                    clear_session(role_type)
                    continue

            # If it's a background polling request, ONLY update the admin session
            if request.headers.get("X-Auto-Refresh") == "1":
                if role_type == "admin":
                    session[f"{prefix}last_active"] = now.isoformat()
            else:
                # Normal user interaction, update the session
                session[f"{prefix}last_active"] = now.isoformat()

    # Security headers (OWASP best practices)
    @app.after_request
    def add_security_headers(response):
        if not SECURITY_HEADERS_ENABLED:
            return response

        # Prevent MIME type sniffing (OWASP)
        response.headers["X-Content-Type-Options"] = "nosniff"

        # XSS Protection fallback for older browsers
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Prevent clickjacking; allow framing only for the SIEM iframe page.
        if request.path != "/admin/siem":
            response.headers["X-Frame-Options"] = "DENY"
        else:
            response.headers["X-Frame-Options"] = "SAMEORIGIN"

        # Referrer policy: don't leak full URLs.
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions policy: disable unnecessary browser features.
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), "
            "payment=(), usb=(), magnetometer=()"
        )

        # Cache control: don't cache authenticated pages.
        if session.get("admin_user_id") or session.get("user_user_id"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"

        # Content Security Policy
        if request.path == "/admin/siem":
            # Allow OpenSearch Dashboards iframe
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                "font-src 'self' https://fonts.gstatic.com; "
                "frame-src http://localhost:5601; "
                "img-src 'self' data:; "
                "connect-src 'self'"
            )
        else:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                "font-src 'self' https://fonts.gstatic.com; "
                "frame-src 'none'; "
                "img-src 'self' data:; "
                "connect-src 'self'"
            )

        return response

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=5000, debug=FLASK_DEBUG)
