import sqlite3
# pyrefly: ignore [missing-import]
from werkzeug.security import generate_password_hash
from config import DATABASE, DEFAULT_ADMIN_USERNAME, DEFAULT_ADMIN_EMAIL, DEFAULT_ADMIN_PASSWORD


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_column_exists(cur, table_name, column_name, alter_sql):
    cur.execute(f"PRAGMA table_info({table_name})")
    cols = [row[1] for row in cur.fetchall()]
    if column_name not in cols:
        cur.execute(alter_sql)


def init_db_and_seed_admin():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'student',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)

    ensure_column_exists(
        cur, "users", "is_active",
        "ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 0"
    )

    cur.execute("""
    CREATE TABLE IF NOT EXISTS courses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        teacher_id INTEGER NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (teacher_id) REFERENCES users(id)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS enrollments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        course_id INTEGER NOT NULL,
        student_id INTEGER NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(course_id, student_id),
        FOREIGN KEY (course_id) REFERENCES courses(id),
        FOREIGN KEY (student_id) REFERENCES users(id)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS ai_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        summary TEXT NOT NULL,
        raw_response TEXT,
        is_read INTEGER NOT NULL DEFAULT 0,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS ip_locks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        purpose TEXT NOT NULL,
        attempt_count INTEGER NOT NULL DEFAULT 0,
        window_start TEXT,
        lock_until TEXT,
        UNIQUE(ip, purpose)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT UNIQUE NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        expires_at TEXT NOT NULL,
        used INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS verification_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        code TEXT NOT NULL,
        purpose TEXT NOT NULL DEFAULT 'password_reset',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        expires_at TEXT NOT NULL,
        used INTEGER NOT NULL DEFAULT 0,
        attempts INTEGER NOT NULL DEFAULT 0
    )
    """)

    conn.commit()

    admin_username = DEFAULT_ADMIN_USERNAME
    admin_email = DEFAULT_ADMIN_EMAIL
    admin_hash = generate_password_hash(DEFAULT_ADMIN_PASSWORD)

    cur.execute("SELECT id FROM users WHERE username = ?", (admin_username,))
    existing_admin = cur.fetchone()

    if not existing_admin:
        cur.execute(
            "INSERT INTO users (username, email, password_hash, role, is_active) VALUES (?, ?, ?, ?, ?)",
            (admin_username, admin_email, admin_hash, "admin", 1)
        )
    else:
        cur.execute(
            "UPDATE users SET role = 'admin', is_active = 1 WHERE username = ?",
            (admin_username,)
        )

    conn.commit()
    conn.close()
