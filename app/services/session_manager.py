"""
Session Manager — Dual-Session Namespacing
============================================
Allows two independent login sessions to coexist in the same browser:
  - Admin session (admin_* keys) for /admin/* routes
  - User session (user_* keys) for /student, /teacher routes

This prevents the common issue where logging in as one user in Tab 2
overwrites the session of another user in Tab 1.

Security: Each session slot has its own idle/absolute timeout tracking.
"""

from flask import session, request
from services.rate_limiter import now_local


# ── Session Key Prefixes ────────────────────────────────────────
ADMIN_PREFIX = "admin_"
USER_PREFIX = "user_"


def _get_prefix_for_role(role):
    """Determine which session slot a role belongs to."""
    if role == "admin":
        return ADMIN_PREFIX
    return USER_PREFIX


def _get_prefix_for_request():
    """Determine which session slot to use based on the current request path."""
    path = request.path if request else "/"
    if path.startswith("/admin"):
        return ADMIN_PREFIX
    return USER_PREFIX


# ── Write Session ───────────────────────────────────────────────
def set_session(user):
    """
    Store user data into the correct session slot based on their role.
    Does NOT clear the other slot — both can coexist.

    Args:
        user: A dict-like row with id, username, role
    """
    role = user["role"]
    prefix = _get_prefix_for_role(role)
    now = now_local().isoformat()

    session[f"{prefix}user_id"] = user["id"]
    session[f"{prefix}username"] = user["username"]
    session[f"{prefix}role"] = user["role"]
    session[f"{prefix}session_start"] = now
    session[f"{prefix}last_active"] = now
    session.permanent = True


# ── Read Session ────────────────────────────────────────────────
def get_session_for_role(role_type):
    """
    Read session data for a specific role type.

    Args:
        role_type: 'admin' or 'user'

    Returns:
        dict with user_id, username, role, session_start, last_active
        or None if no session exists for that slot.
    """
    prefix = ADMIN_PREFIX if role_type == "admin" else USER_PREFIX
    user_id = session.get(f"{prefix}user_id")
    if not user_id:
        return None
    return {
        "user_id": user_id,
        "username": session.get(f"{prefix}username", ""),
        "role": session.get(f"{prefix}role", ""),
        "session_start": session.get(f"{prefix}session_start", ""),
        "last_active": session.get(f"{prefix}last_active", ""),
    }


def get_session_by_prefix(prefix):
    """
    Read session data for a specific prefix.

    Args:
        prefix: ADMIN_PREFIX or USER_PREFIX

    Returns:
        dict with user_id, username, role, etc. or None
    """
    user_id = session.get(f"{prefix}user_id")
    if not user_id:
        return None
    return {
        "user_id": user_id,
        "username": session.get(f"{prefix}username", ""),
        "role": session.get(f"{prefix}role", ""),
        "session_start": session.get(f"{prefix}session_start", ""),
        "last_active": session.get(f"{prefix}last_active", ""),
    }


def get_current_session():
    """
    Get the session that applies to the current request path.

    For /admin/* routes → read admin slot
    For everything else → read user slot
    """
    prefix = _get_prefix_for_request()
    return get_session_by_prefix(prefix)


# ── Clear Session ───────────────────────────────────────────────
def clear_session(role_type):
    """
    Clear only one session slot, leaving the other intact.

    Args:
        role_type: 'admin' or 'user'
    """
    prefix = ADMIN_PREFIX if role_type == "admin" else USER_PREFIX
    keys_to_remove = [k for k in session if k.startswith(prefix)]
    for k in keys_to_remove:
        session.pop(k, None)


def clear_all_sessions():
    """Clear both session slots completely."""
    session.clear()


# ── Update Activity ─────────────────────────────────────────────
def update_last_active(prefix):
    """Update the last_active timestamp for a specific session slot."""
    session[f"{prefix}last_active"] = now_local().isoformat()


# ── Auth Helpers for Route Guards ───────────────────────────────
def is_admin_logged_in():
    """Check if an admin session is active."""
    return session.get(f"{ADMIN_PREFIX}user_id") is not None


def is_user_logged_in():
    """Check if a user (student/teacher) session is active."""
    return session.get(f"{USER_PREFIX}user_id") is not None


def get_admin_session():
    """Get admin session data."""
    return get_session_for_role("admin")


def get_user_session():
    """Get user (student/teacher) session data."""
    return get_session_for_role("user")


def admin_user_id():
    """Quick access to admin user_id."""
    return session.get(f"{ADMIN_PREFIX}user_id")


def admin_username():
    """Quick access to admin username."""
    return session.get(f"{ADMIN_PREFIX}username", "")


def admin_role():
    """Quick access to admin role."""
    return session.get(f"{ADMIN_PREFIX}role", "")


def user_user_id():
    """Quick access to user user_id."""
    return session.get(f"{USER_PREFIX}user_id")


def user_username():
    """Quick access to user username."""
    return session.get(f"{USER_PREFIX}username", "")


def user_role():
    """Quick access to user role."""
    return session.get(f"{USER_PREFIX}role", "")
