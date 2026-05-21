from datetime import datetime, timedelta
from models import get_db


def now_local():
    return datetime.now()


def parse_dt(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None


def get_ip_lock(ip, purpose):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM ip_locks WHERE ip = ? AND purpose = ?", (ip, purpose))
    row = cur.fetchone()
    conn.close()
    return row


def is_ip_locked(ip, purpose):
    row = get_ip_lock(ip, purpose)
    if not row:
        return False, None
    lock_until = parse_dt(row["lock_until"])
    if lock_until and now_local() < lock_until:
        return True, lock_until
    return False, None


def clear_ip_attempts(ip, purpose):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        UPDATE ip_locks
        SET attempt_count = 0, window_start = NULL, lock_until = NULL
        WHERE ip = ? AND purpose = ?
    """, (ip, purpose))
    conn.commit()
    conn.close()


def register_ip_attempt(ip, purpose, threshold=5, window_minutes=2, lock_minutes=3):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM ip_locks WHERE ip = ? AND purpose = ?", (ip, purpose))
    row = cur.fetchone()

    now = now_local()

    if not row:
        cur.execute("""
            INSERT INTO ip_locks (ip, purpose, attempt_count, window_start, lock_until)
            VALUES (?, ?, ?, ?, ?)
        """, (ip, purpose, 1, now.isoformat(), None))
        conn.commit()
        conn.close()
        return {"locked_now": False, "count": 1, "lock_until": None}

    current_lock_until = parse_dt(row["lock_until"])
    if current_lock_until and now < current_lock_until:
        conn.close()
        return {"locked_now": False, "count": row["attempt_count"], "lock_until": current_lock_until}

    window_start = parse_dt(row["window_start"])
    if window_start and now - window_start <= timedelta(minutes=window_minutes):
        new_count = int(row["attempt_count"]) + 1
    else:
        new_count = 1
        window_start = now

    lock_until = None
    locked_now = False

    if new_count > threshold:
        lock_until = now + timedelta(minutes=lock_minutes)
        locked_now = True

    cur.execute("""
        UPDATE ip_locks
        SET attempt_count = ?, window_start = ?, lock_until = ?
        WHERE ip = ? AND purpose = ?
    """, (
        new_count,
        window_start.isoformat() if window_start else None,
        lock_until.isoformat() if lock_until else None,
        ip,
        purpose
    ))
    conn.commit()
    conn.close()

    return {"locked_now": locked_now, "count": new_count, "lock_until": lock_until}
