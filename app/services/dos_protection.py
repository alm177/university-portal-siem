"""
DoS (Denial of Service) Protection Module

Tracks HTTP request rates per IP using an in-memory sliding window.
When an IP exceeds the warning threshold, a SIEM event is logged.
When an IP exceeds the block threshold, the IP is temporarily blocked.
"""

import threading
from collections import defaultdict
from datetime import datetime, timedelta


# ── In-memory stores (thread-safe) ──────────────────────────────
_lock = threading.Lock()
_request_log = defaultdict(list)      # ip -> [timestamp, ...]
_blocked_ips = {}                      # ip -> unblock_datetime
_warned_ips = {}                       # ip -> last_warning_datetime (rate limit warnings)


def _cleanup_old_entries(ip, window_seconds):
    """Remove timestamps older than the sliding window."""
    cutoff = datetime.now() - timedelta(seconds=window_seconds)
    _request_log[ip] = [t for t in _request_log[ip] if t > cutoff]


def record_request(ip, window_seconds, warning_threshold, block_threshold, block_minutes):
    """
    Record a request from an IP and check thresholds.

    Returns:
        tuple: (status, request_count)
            status is one of: 'normal', 'warning', 'blocked_new', 'blocked_existing'
    """
    now = datetime.now()

    with _lock:
        # Check if IP is already blocked
        if ip in _blocked_ips:
            if now < _blocked_ips[ip]:
                return ('blocked_existing', 0)
            else:
                # Block expired
                del _blocked_ips[ip]
                _warned_ips.pop(ip, None)
                return ('block_expired', 0)

        # Record the request
        _request_log[ip].append(now)
        _cleanup_old_entries(ip, window_seconds)
        count = len(_request_log[ip])

        # Check block threshold
        if count >= block_threshold:
            _blocked_ips[ip] = now + timedelta(minutes=block_minutes)
            _request_log[ip].clear()
            return ('blocked_new', count)

        # Check warning threshold (rate-limit to one warning per 30 seconds per IP)
        if count >= warning_threshold:
            last_warn = _warned_ips.get(ip)
            if not last_warn or (now - last_warn).total_seconds() > 30:
                _warned_ips[ip] = now
                return ('warning', count)

        return ('normal', count)


def is_ip_blocked(ip):
    """Check if an IP is currently DoS-blocked."""
    with _lock:
        if ip in _blocked_ips:
            if datetime.now() < _blocked_ips[ip]:
                return True
            else:
                del _blocked_ips[ip]
        return False


def get_dos_stats():
    """Return current DoS monitoring state for the dashboard."""
    now = datetime.now()
    with _lock:
        active_blocks = {
            ip: expires.isoformat()
            for ip, expires in _blocked_ips.items()
            if now < expires
        }
        active_warnings = len(_warned_ips)
        tracked_ips = len(_request_log)

    return {
        "blocked_ips": active_blocks,
        "blocked_count": len(active_blocks),
        "warned_ips_count": active_warnings,
        "tracked_ips": tracked_ips
    }


def unblock_ip(ip):
    """Manually unblock an IP."""
    with _lock:
        _blocked_ips.pop(ip, None)
        _warned_ips.pop(ip, None)


def get_blocked_list():
    """Return list of currently blocked IPs with expiry times."""
    now = datetime.now()
    with _lock:
        return [
            {"ip": ip, "expires": expires.isoformat(), "remaining_seconds": max(0, (expires - now).total_seconds())}
            for ip, expires in _blocked_ips.items()
            if now < expires
        ]
