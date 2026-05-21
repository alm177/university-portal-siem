from flask import Blueprint, render_template, make_response, redirect, url_for
from models import get_db
from services.siem import send_log
from services.session_manager import is_user_logged_in, get_user_session, user_username, user_role, user_user_id

student_bp = Blueprint('student', __name__)


def login_required():
    return is_user_logged_in()


def role_required(role):
    return user_role() == role


def deny_access(requested_path, reason):
    if reason == "not_logged_in":
        return redirect(url_for("auth.login", expired="idle"))
        
    user_sess = get_user_session()
    user = user_sess["username"] if user_sess else "anonymous"
    role = user_sess["role"] if user_sess else "unknown"
    send_log("access_denied", user, role, False, reason, {"requested_path": requested_path})
    html = render_template("access_denied.html", path=requested_path, role=role, user=user, logged_in=login_required())
    return make_response(html, 403)


@student_bp.route("/student")
def student_page():
    if not login_required():
        return deny_access("/student", "not_logged_in")
    if not role_required("student"):
        return deny_access("/student", "role_not_allowed")

    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        SELECT c.name, c.description, t.username AS teacher_username
        FROM enrollments e
        JOIN courses c ON e.course_id = c.id
        JOIN users t ON c.teacher_id = t.id
        WHERE e.student_id = ?
        ORDER BY c.id DESC
    """, (user_user_id(),))
    courses = cur.fetchall()
    conn.close()

    return render_template("student.html", username=user_username(), role=user_role(), courses=courses)
