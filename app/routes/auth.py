"""
Authentication Routes
=====================
Handles login, registration, logout, password reset, and email verification.

Security features implemented:
  - CAPTCHA validation (anti-bot)
  - IP-based rate limiting (NIST SP 800-53 AC-7)
  - Email MFA for registration (NIST SP 800-63B)
  - 6-digit verification codes for password reset
  - Password policy enforcement (OWASP guidelines)
  - Generic error messages (prevent user enumeration)
  - Per-username attack tracking (credential stuffing detection)
"""

import re
import random
import secrets
from datetime import datetime, timedelta
from flask import Blueprint, request, redirect, url_for, render_template, session, make_response
from werkzeug.security import generate_password_hash, check_password_hash

from models import get_db
from services.siem import send_log, get_client_ip
from services.rate_limiter import is_ip_locked, clear_ip_attempts, register_ip_attempt, now_local, parse_dt
from services.session_manager import (
    set_session, get_session_for_role, clear_session,
    is_admin_logged_in, is_user_logged_in,
    get_admin_session, get_user_session,
    ADMIN_PREFIX, USER_PREFIX
)
from services.email_service import send_reset_code, send_registration_code, send_change_password_code
from config import (
    LOGIN_THRESHOLD, REGISTER_THRESHOLD, RESET_THRESHOLD,
    WINDOW_MINUTES, LOCK_MINUTES, RESET_WINDOW_MINUTES,
    RESET_TOKEN_EXPIRE_MINUTES,
    VERIFICATION_CODE_EXPIRE_MINUTES, VERIFICATION_CODE_MAX_ATTEMPTS
)

auth_bp = Blueprint('auth', __name__)


def _redirect_if_authenticated():
    """
    If a user is already logged in (in BOTH slots), redirect to dashboard.
    If only one slot is active, allow access to login so the other role can log in.
    Returns a redirect response or None.
    """
    user_sess = get_user_session()
    admin_sess = get_admin_session()
    # Only redirect if both slots are occupied
    if user_sess and admin_sess:
        # Prefer redirecting to admin dashboard
        return redirect(url_for("admin.admin_page"))
    return None


def _redirect_if_any_authenticated():
    """
    Redirect if ANY session slot is active.
    Used for pages where authenticated users should not access (register, forgot-password).
    """
    user_sess = get_user_session()
    if user_sess:
        role = user_sess["role"]
        if role == "teacher":
            return redirect(url_for("teacher.teacher_page"))
        return redirect(url_for("student.student_page"))
    admin_sess = get_admin_session()
    if admin_sess:
        return redirect(url_for("admin.admin_page"))
    return None


def generate_captcha():
    a = random.randint(1, 9)
    b = random.randint(1, 9)
    session["captcha_answer"] = str(a + b)
    return f"What is {a} + {b}?"


def password_policy_ok(password):
    """
    Enforce OWASP-recommended password policy:
      - Minimum 8 characters
      - At least one uppercase, one lowercase, one digit, one special char
    """
    if len(password) < 8:
        return False
    return (
        any(c.isupper() for c in password) and
        any(c.islower() for c in password) and
        any(c.isdigit() for c in password) and
        bool(re.search(r"[^A-Za-z0-9]", password))
    )


def _generate_verification_code():
    """Generate a cryptographically secure 6-digit verification code."""
    return f"{secrets.randbelow(900000) + 100000}"


def _store_verification_code(email, code, purpose):
    """Store a verification code in the database with expiry."""
    conn = get_db()
    cur = conn.cursor()
    expires = (now_local() + timedelta(minutes=VERIFICATION_CODE_EXPIRE_MINUTES)).isoformat()

    # Invalidate any existing unused codes for this email + purpose
    cur.execute(
        "UPDATE verification_codes SET used = 1 WHERE email = ? AND purpose = ? AND used = 0",
        (email, purpose)
    )

    cur.execute(
        "INSERT INTO verification_codes (email, code, purpose, expires_at) VALUES (?, ?, ?, ?)",
        (email, code, purpose, expires)
    )
    conn.commit()
    conn.close()


def _verify_code(email, code, purpose):
    """
    Verify a 6-digit code. Returns (success, error_message).
    Implements brute-force protection on code verification attempts.
    """
    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "SELECT * FROM verification_codes WHERE email = ? AND purpose = ? AND used = 0 ORDER BY id DESC LIMIT 1",
        (email, purpose)
    )
    row = cur.fetchone()

    if not row:
        conn.close()
        return False, "No verification code found. Please request a new one."

    # Check expiry
    expires = parse_dt(row["expires_at"])
    if not expires or now_local() > expires:
        cur.execute("UPDATE verification_codes SET used = 1 WHERE id = ?", (row["id"],))
        conn.commit()
        conn.close()
        return False, "Verification code has expired. Please request a new one."

    # Check attempts (brute-force protection)
    attempts = int(row["attempts"])
    if attempts >= VERIFICATION_CODE_MAX_ATTEMPTS:
        cur.execute("UPDATE verification_codes SET used = 1 WHERE id = ?", (row["id"],))
        conn.commit()
        conn.close()
        return False, "Too many incorrect attempts. Please request a new code."

    # Check code
    if row["code"] != code.strip():
        cur.execute(
            "UPDATE verification_codes SET attempts = attempts + 1 WHERE id = ?",
            (row["id"],)
        )
        conn.commit()
        conn.close()
        remaining = VERIFICATION_CODE_MAX_ATTEMPTS - attempts - 1
        return False, f"Incorrect code. {remaining} attempt(s) remaining."

    # Code is correct — mark as used
    cur.execute("UPDATE verification_codes SET used = 1 WHERE id = ?", (row["id"],))
    conn.commit()
    conn.close()
    return True, None


# ========= Login =========
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    # Redirect already-authenticated users to their dashboard
    redir = _redirect_if_authenticated()
    if redir:
        return redir

    generic_fail = "Username or Password is wrong"
    ip = get_client_ip()
    
    msg = None
    if request.args.get("expired") == "idle":
        msg = "You have been logged out due to inactivity."

    if request.method == "POST":
        locked, lock_until = is_ip_locked(ip, "login")
        if locked:
            return render_template(
                "login.html",
                msg=f"Too many failed login attempts from your IP. Try again after {lock_until.strftime('%H:%M:%S')}."
            )

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()

        if not user:
            attempt_info = register_ip_attempt(ip, "login", LOGIN_THRESHOLD, WINDOW_MINUTES, LOCK_MINUTES)
            if attempt_info["locked_now"]:
                send_log("ip_locked_login", username, "unknown", False, "too_many_failed_logins", {
                    "ip_lock_until": attempt_info["lock_until"].isoformat(),
                    "attempt_count": attempt_info["count"]
                })
            conn.close()
            send_log("login_failed", username, "unknown", False, "user_not_found")
            return render_template("login.html", msg=generic_fail)

        # Check account status: -1 = pending email, 0 = pending admin, 1 = active
        if int(user["is_active"]) == -1:
            conn.close()
            send_log("login_failed", user["username"], user["role"], False, "email_not_verified")
            return render_template("login.html", msg="Please verify your email address first.")

        if not int(user["is_active"]):
            conn.close()
            send_log("login_failed", user["username"], user["role"], False, "account_disabled_or_pending")
            return render_template("login.html", msg=generic_fail)

        if check_password_hash(user["password_hash"], password):
            clear_ip_attempts(ip, "login")
            conn.close()

            # Store session in the correct namespace slot
            # Admin goes to admin_* keys, student/teacher goes to user_* keys
            # This allows both to coexist in the same browser
            set_session(user)

            send_log("login_success", user["username"], user["role"], True, "ok")

            if user["role"] == "admin":
                return redirect(url_for("admin.admin_page"))
            elif user["role"] == "teacher":
                return redirect(url_for("teacher.teacher_page"))
            return redirect(url_for("student.student_page"))

        attempt_info = register_ip_attempt(ip, "login", LOGIN_THRESHOLD, WINDOW_MINUTES, LOCK_MINUTES)
        if attempt_info["locked_now"]:
            send_log("ip_locked_login", user["username"], user["role"], False, "too_many_failed_logins", {
                "ip_lock_until": attempt_info["lock_until"].isoformat(),
                "attempt_count": attempt_info["count"]
            })

        conn.close()
        send_log("login_failed", user["username"], user["role"], False, "wrong_password")
        return render_template("login.html", msg=generic_fail)

    return render_template("login.html", msg=msg)


# ========= Register =========
@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    # Redirect already-authenticated users to their dashboard
    redir = _redirect_if_any_authenticated()
    if redir:
        return redir

    msg, ok = None, False
    ip = get_client_ip()

    if request.method == "GET":
        locked, lock_until = is_ip_locked(ip, "register")
        captcha_question = generate_captcha()
        if locked:
            return render_template(
                "register.html",
                msg=f"Too many registration attempts from your IP. Try again after {lock_until.strftime('%H:%M:%S')}.",
                ok=False,
                captcha_question=captcha_question
            )
        return render_template("register.html", msg=None, ok=False, captcha_question=captcha_question)

    # POST
    locked, lock_until = is_ip_locked(ip, "register")
    if locked:
        captcha_question = generate_captcha()
        return render_template(
            "register.html",
            msg=f"Too many registration attempts from your IP. Try again after {lock_until.strftime('%H:%M:%S')}.",
            ok=False,
            captcha_question=captcha_question
        )

    attempt_info = register_ip_attempt(ip, "register", REGISTER_THRESHOLD, WINDOW_MINUTES, LOCK_MINUTES)
    if attempt_info["locked_now"]:
        send_log("ip_locked_registration", "anonymous", "unknown", False, "too_many_registration_attempts", {
            "ip_lock_until": attempt_info["lock_until"].isoformat(),
            "attempt_count": attempt_info["count"]
        })
        captcha_question = generate_captcha()
        return render_template(
            "register.html",
            msg=f"Too many registration attempts from your IP. Try again after {attempt_info['lock_until'].strftime('%H:%M:%S')}.",
            ok=False,
            captcha_question=captcha_question
        )

    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    requested_role = request.form.get("role", "student").strip().lower()
    captcha_answer = request.form.get("captcha_answer", "").strip()

    if captcha_answer != session.get("captcha_answer", ""):
        captcha_question = generate_captcha()
        send_log("user_register_failed", username or "anonymous", requested_role, False, "captcha_failed")
        return render_template("register.html", msg="Incorrect CAPTCHA answer.", ok=False, captcha_question=captcha_question)

    role = requested_role if requested_role in ("student", "teacher") else "student"

    if len(username) < 3:
        msg = "Username must be at least 3 characters long."
        send_log("user_register_failed", username or "anonymous", role, False, "short_username")
    elif not password_policy_ok(password):
        msg = "Password does not meet the required policy."
        send_log("user_register_failed", username or "anonymous", role, False, "weak_password")
    elif not email or "@" not in email:
        msg = "Please provide a valid email address."
        send_log("user_register_failed", username or "anonymous", role, False, "invalid_email")
    else:
        import sqlite3
        ph = generate_password_hash(password)
        conn = get_db()
        cur = conn.cursor()
        try:
            # is_active = -1 means pending email verification (Email MFA)
            cur.execute(
                "INSERT INTO users (username, email, password_hash, role, is_active) VALUES (?, ?, ?, ?, ?)",
                (username, email, ph, role, -1)
            )
            conn.commit()

            # Generate and send email verification code
            code = _generate_verification_code()
            _store_verification_code(email, code, "email_verification")

            sent, err = send_registration_code(email, code, username)

            send_log("user_register", username, role, True, "created_pending_email_verification")

            if sent:
                # Email sent successfully
                session["verify_email"] = email
                return redirect(url_for("auth.verify_email"))
            else:
                # Email failed to send
                session["verify_email"] = email
                captcha_question = generate_captcha()
                return render_template("register.html",
                    msg="Account created, but failed to send verification email. Please contact support.",
                    ok=False,
                    captcha_question=captcha_question,
                    show_verify_link=True
                )

        except sqlite3.IntegrityError:
            msg = "Username or email is already in use."
            send_log("user_register_failed", username, role, False, "duplicate")
        except Exception as e:
            msg = "An unexpected error occurred during registration."
            send_log("user_register_failed", username, role, False, "error", {"error": str(e)})
        finally:
            conn.close()

    captcha_question = generate_captcha()
    return render_template("register.html", msg=msg, ok=ok, captcha_question=captcha_question)


# ========= Verify Email (Registration MFA) =========
@auth_bp.route("/verify-email", methods=["GET", "POST"])
def verify_email():
    # Redirect already-authenticated users to their dashboard
    redir = _redirect_if_any_authenticated()
    if redir:
        return redir

    email = session.get("verify_email", "")
    ip = get_client_ip()

    if request.method == "POST":
        email_input = request.form.get("email", "").strip()
        code = request.form.get("code", "").strip()

        if not email_input or not code:
            return render_template("verify_email.html", email=email_input,
                msg="Please enter your email and verification code.", ok=False)

        success, error = _verify_code(email_input, code, "email_verification")

        if success:
            # Upgrade account from pending_email (-1) to pending_admin (0)
            conn = get_db()
            cur = conn.cursor()
            cur.execute(
                "UPDATE users SET is_active = 0 WHERE email = ? AND is_active = -1",
                (email_input,)
            )
            conn.commit()

            # Get username for logging
            cur.execute("SELECT username, role FROM users WHERE email = ?", (email_input,))
            user = cur.fetchone()
            conn.close()

            if user:
                send_log("email_verified", user["username"], user["role"], True, "email_mfa_passed")

            session.pop("verify_email", None)
            return render_template("verify_email.html", email=email_input,
                msg="Email verified successfully! Your account is now pending administrator approval.",
                ok=True)
        else:
            send_log("email_verification_failed", "anonymous", "unknown", False, "wrong_code", {
                "email": email_input,
                "error": error
            })
            return render_template("verify_email.html", email=email_input, msg=error, ok=False)

    return render_template("verify_email.html", email=email, msg=None, ok=False)


# ========= Logout =========
@auth_bp.route("/logout")
def logout():
    """Scoped logout: clears only the session slot specified by ?ctx= param."""
    ctx = request.args.get("ctx", "user")
    if ctx == "admin":
        admin_sess = get_admin_session()
        if admin_sess:
            send_log("logout", admin_sess["username"], "admin", True, "ok")
        clear_session("admin")
    else:
        user_sess = get_user_session()
        if user_sess:
            send_log("logout", user_sess["username"], user_sess.get("role", "unknown"), True, "ok")
        clear_session("user")
    return redirect(url_for("auth.login"))


# ========= Forgot Password =========
@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    # Redirect already-authenticated users to their dashboard
    redir = _redirect_if_any_authenticated()
    if redir:
        return redir

    msg, ok = None, False
    ip = get_client_ip()

    if request.method == "POST":
        locked, lock_until = is_ip_locked(ip, "password_reset")
        if locked:
            send_log("password_reset_rate_limited", "anonymous", "unknown", False, "ip_locked", {"ip": ip})
            return render_template("forgot_password.html",
                msg=f"Too many reset requests. Try again after {lock_until.strftime('%H:%M:%S')}.",
                ok=False)

        attempt_info = register_ip_attempt(ip, "password_reset", RESET_THRESHOLD, RESET_WINDOW_MINUTES, LOCK_MINUTES)
        if attempt_info["locked_now"]:
            send_log("password_reset_rate_limited", "anonymous", "unknown", False, "too_many_requests", {"ip": ip})
            return render_template("forgot_password.html",
                msg=f"Too many reset requests. Try again after {attempt_info['lock_until'].strftime('%H:%M:%S')}.",
                ok=False)

        email = request.form.get("email", "").strip()
        send_log("password_reset_requested", "anonymous", "unknown", True, "email_submitted", {"email": email})

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cur.fetchone()
        conn.close()

        if user:
            code = _generate_verification_code()
            _store_verification_code(email, code, "password_reset")

            sent, err = send_reset_code(email, code)

            if sent:
                msg = "A verification code has been sent to your email address."
                ok = True
                session["reset_email"] = email
                send_log("password_reset_code_sent", user["username"], user["role"], True, "code_sent_via_email")
            else:
                # Failed to send email
                msg = "Failed to send verification email. Please contact support."
                ok = False
                send_log("password_reset_code_failed", user["username"], user["role"], False, "email_send_failed")
        else:
            # Don't reveal whether the email exists (prevent enumeration)
            msg = "If that email is registered, a verification code has been sent."
            ok = True
            send_log("password_reset_requested", "anonymous", "unknown", False, "email_not_found", {"email": email})

    return render_template("forgot_password.html", msg=msg, ok=ok)


# ========= Verify Reset Code =========
@auth_bp.route("/verify-reset-code", methods=["GET", "POST"])
def verify_reset_code():
    # Redirect already-authenticated users to their dashboard
    redir = _redirect_if_any_authenticated()
    if redir:
        return redir

    email = session.get("reset_email", "")

    if request.method == "POST":
        email_input = request.form.get("email", "").strip()
        code = request.form.get("code", "").strip()

        if not email_input or not code:
            return render_template("verify_code.html", email=email_input,
                msg="Please enter your email and verification code.", ok=False)

        success, error = _verify_code(email_input, code, "password_reset")

        if success:
            # Generate a one-time token for the password reset form
            token = secrets.token_urlsafe(32)
            expires_at = (now_local() + timedelta(minutes=RESET_TOKEN_EXPIRE_MINUTES)).isoformat()

            conn = get_db()
            cur = conn.cursor()
            cur.execute("SELECT id FROM users WHERE email = ?", (email_input,))
            user = cur.fetchone()
            if user:
                cur.execute(
                    "INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
                    (user["id"], token, expires_at)
                )
                conn.commit()
            conn.close()

            send_log("password_reset_code_verified", "anonymous", "unknown", True, "code_verified")
            session.pop("reset_email", None)
            return redirect(url_for("auth.reset_password", token=token))
        else:
            send_log("password_reset_code_failed", "anonymous", "unknown", False, "wrong_code", {
                "email": email_input,
                "error": error
            })
            return render_template("verify_code.html", email=email_input, msg=error, ok=False)

    return render_template("verify_code.html", email=email, msg=None, ok=False)


# ========= Reset Password =========
@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    # Redirect already-authenticated users to their dashboard
    redir = _redirect_if_any_authenticated()
    if redir:
        return redir

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM password_reset_tokens WHERE token = ? AND used = 0", (token,))
    token_row = cur.fetchone()

    if not token_row:
        conn.close()
        send_log("password_reset_failed", "anonymous", "unknown", False, "invalid_token")
        return render_template("reset_password.html", valid=False, msg="Invalid or already used reset link.", ok=False)

    expires_at = parse_dt(token_row["expires_at"])
    if not expires_at or now_local() > expires_at:
        conn.close()
        send_log("password_reset_failed", "anonymous", "unknown", False, "expired_token")
        return render_template("reset_password.html", valid=False, msg="This reset link has expired.", ok=False)

    if request.method == "POST":
        password = request.form.get("password", "")
        password_confirm = request.form.get("password_confirm", "")

        if password != password_confirm:
            conn.close()
            return render_template("reset_password.html", valid=True, msg="Passwords do not match.", ok=False)

        if not password_policy_ok(password):
            conn.close()
            return render_template("reset_password.html", valid=True, msg="Password does not meet the required policy.", ok=False)

        # Password history check — prevent reuse of current password
        cur.execute("SELECT password_hash FROM users WHERE id = ?", (token_row["user_id"],))
        current_user = cur.fetchone()
        if current_user and check_password_hash(current_user["password_hash"], password):
            conn.close()
            return render_template("reset_password.html", valid=True,
                msg="New password cannot be the same as your current password.", ok=False)

        new_hash = generate_password_hash(password)
        cur.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, token_row["user_id"]))
        cur.execute("UPDATE password_reset_tokens SET used = 1 WHERE id = ?", (token_row["id"],))
        conn.commit()

        # Get username for logging
        cur.execute("SELECT username, role FROM users WHERE id = ?", (token_row["user_id"],))
        user = cur.fetchone()
        conn.close()

        if user:
            send_log("password_reset_success", user["username"], user["role"], True, "password_changed")
        return render_template("reset_password.html", valid=False,
            msg="Password reset successfully! You can now sign in with your new password.", ok=True)

    conn.close()
    return render_template("reset_password.html", valid=True, msg=None, ok=False)


# ========= Change Password (Authenticated Users) =========
@auth_bp.route("/change-password", methods=["GET", "POST"])
def change_password():
    """
    Step 1: Verify old password, validate new password, send email verification code.
    Accessible to any authenticated user (admin, teacher, or student).
    """
    # Determine which session slot is active
    admin_sess = get_admin_session()
    user_sess = get_user_session()
    current_sess = admin_sess or user_sess

    if not current_sess:
        return redirect(url_for("auth.login"))

    user_id = current_sess["user_id"]
    username = current_sess["username"]
    role = current_sess["role"]

    if request.method == "POST":
        old_password = request.form.get("old_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cur.fetchone()
        conn.close()

        if not user:
            return render_template("change_password.html", username=username, role=role,
                msg="User account not found.", ok=False)

        # Verify old password
        if not check_password_hash(user["password_hash"], old_password):
            send_log("change_password_failed", username, role, False, "wrong_old_password")
            return render_template("change_password.html", username=username, role=role,
                msg="Current password is incorrect.", ok=False)

        # Validate new password
        if new_password != confirm_password:
            return render_template("change_password.html", username=username, role=role,
                msg="New passwords do not match.", ok=False)

        if not password_policy_ok(new_password):
            return render_template("change_password.html", username=username, role=role,
                msg="New password does not meet the required policy.", ok=False)

        # Check new password is not same as old
        if check_password_hash(user["password_hash"], new_password):
            return render_template("change_password.html", username=username, role=role,
                msg="New password cannot be the same as your current password.", ok=False)

        # All checks passed — send verification code to email
        email = user["email"]
        code = _generate_verification_code()
        _store_verification_code(email, code, "change_password")

        sent, err = send_change_password_code(email, code, username)

        # Store the new password hash temporarily in session for step 2
        new_hash = generate_password_hash(new_password)
        session["change_pw_user_id"] = user_id
        session["change_pw_email"] = email
        session["change_pw_new_hash"] = new_hash
        session["change_pw_username"] = username
        session["change_pw_role"] = role

        if sent:
            send_log("change_password_code_sent", username, role, True, "verification_code_sent")
            return redirect(url_for("auth.change_password_verify"))
        else:
            send_log("change_password_code_failed", username, role, False, "email_send_failed")
            return render_template("change_password.html", username=username, role=role,
                msg="Failed to send verification email. Please try again.", ok=False)

    return render_template("change_password.html", username=username, role=role, msg=None, ok=False)


@auth_bp.route("/change-password/verify", methods=["GET", "POST"])
def change_password_verify():
    """
    Step 2: Verify the 6-digit email code and apply the password change.
    """
    # Check that step 1 was completed
    cp_user_id = session.get("change_pw_user_id")
    cp_email = session.get("change_pw_email")
    cp_new_hash = session.get("change_pw_new_hash")
    cp_username = session.get("change_pw_username", "unknown")
    cp_role = session.get("change_pw_role", "unknown")

    if not cp_user_id or not cp_email or not cp_new_hash:
        return redirect(url_for("auth.change_password"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()

        if not code:
            return render_template("change_password_verify.html", email=cp_email,
                msg="Please enter the verification code.", ok=False)

        success, error = _verify_code(cp_email, code, "change_password")

        if success:
            # Apply the password change
            conn = get_db()
            cur = conn.cursor()
            cur.execute("UPDATE users SET password_hash = ? WHERE id = ?", (cp_new_hash, cp_user_id))
            conn.commit()
            conn.close()

            send_log("change_password_success", cp_username, cp_role, True, "password_changed")

            # Clean up session keys
            for key in ["change_pw_user_id", "change_pw_email", "change_pw_new_hash",
                        "change_pw_username", "change_pw_role"]:
                session.pop(key, None)

            return render_template("change_password_verify.html", email=cp_email,
                msg="Password changed successfully! Please sign in again with your new password.", ok=True)
        else:
            send_log("change_password_verify_failed", cp_username, cp_role, False, "wrong_code", {
                "error": error
            })
            return render_template("change_password_verify.html", email=cp_email,
                msg=error, ok=False)

    return render_template("change_password_verify.html", email=cp_email, msg=None, ok=False)
