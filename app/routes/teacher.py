import sqlite3
# pyrefly: ignore [missing-import]
from flask import Blueprint, request, render_template, make_response, redirect, url_for
from models import get_db
from services.siem import send_log
from services.session_manager import is_user_logged_in, get_user_session, user_username, user_role, user_user_id

teacher_bp = Blueprint('teacher', __name__)


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


@teacher_bp.route("/teacher", methods=["GET", "POST"])
def teacher_page():
    if not login_required():
        return deny_access("/teacher", "not_logged_in")
    if not role_required("teacher"):
        return deny_access("/teacher", "role_not_allowed")

    msg, ok = None, False
    teacher_id = user_user_id()
    conn = get_db()
    cur = conn.cursor()

    if request.method == "POST":
        action = request.form.get("action", "")

        if action == "create_course":
            course_name = request.form.get("course_name", "").strip()
            course_description = request.form.get("course_description", "").strip()
            if course_name:
                cur.execute(
                    "INSERT INTO courses (name, description, teacher_id) VALUES (?, ?, ?)",
                    (course_name, course_description, teacher_id)
                )
                conn.commit()
                msg, ok = "Course created successfully.", True
                send_log("course_created", user_username(), "teacher", True, "course_created", {
                    "course_name": course_name
                })

        elif action == "enroll_student":
            course_id = request.form.get("course_id", "").strip()
            student_id = request.form.get("student_id", "").strip()
            try:
                cur.execute("SELECT * FROM courses WHERE id = ? AND teacher_id = ?", (course_id, teacher_id))
                course = cur.fetchone()
                cur.execute("SELECT * FROM users WHERE id = ? AND role = 'student'", (student_id,))
                student = cur.fetchone()
                if course and student:
                    cur.execute("INSERT INTO enrollments (course_id, student_id) VALUES (?, ?)", (course_id, student_id))
                    conn.commit()
                    msg, ok = "Student enrolled successfully.", True
                    send_log("student_enrolled", user_username(), "teacher", True, "student_enrolled", {
                        "course_name": course["name"], "student_username": student["username"]
                    })
            except sqlite3.IntegrityError:
                msg, ok = "This student is already enrolled in that course.", False

    cur.execute("""
        SELECT c.id, c.name, c.description,
               (SELECT COUNT(*) FROM enrollments e WHERE e.course_id = c.id) AS student_count
        FROM courses c WHERE c.teacher_id = ? ORDER BY c.id DESC
    """, (teacher_id,))
    teacher_courses = cur.fetchall()

    cur.execute("SELECT id, username FROM users WHERE role = 'student' ORDER BY username ASC")
    students = cur.fetchall()

    cur.execute("SELECT id, name FROM courses WHERE teacher_id = ? ORDER BY id DESC", (teacher_id,))
    courses = cur.fetchall()
    conn.close()

    return render_template("teacher.html", username=user_username(), role=user_role(),
                           msg=msg, ok=ok, teacher_courses=teacher_courses, students=students, courses=courses)
