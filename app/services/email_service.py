"""
Email Service Module
====================
Handles sending verification codes via SMTP for:
  - Password reset (forgot password flow)
  - Email MFA (registration verification)

Follows NIST SP 800-63B guidelines for verification code delivery.
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config import SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM


def is_smtp_configured():
    """Check if SMTP credentials are configured."""
    return bool(SMTP_SERVER and SMTP_USER and SMTP_PASS)


def _send_email(to_email, subject, html_body, text_body):
    """
    Send an email via SMTP. Returns (success, error_message).
    Implements TLS encryption per OWASP secure communication guidelines.
    """
    if not is_smtp_configured():
        return False, "SMTP not configured"

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = SMTP_FROM
        msg["To"] = to_email

        # Plain text fallback
        msg.attach(MIMEText(text_body, "plain"))
        # Rich HTML version
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_FROM, to_email, msg.as_string())

        return True, None

    except smtplib.SMTPAuthenticationError:
        return False, "SMTP authentication failed"
    except smtplib.SMTPRecipientsRefused:
        return False, "Recipient address refused"
    except smtplib.SMTPException as e:
        return False, f"SMTP error: {str(e)}"
    except Exception as e:
        return False, f"Email send error: {str(e)}"


def send_reset_code(email, code):
    """
    Send a password reset verification code.
    Returns (sent_via_email: bool, error: str|None).
    """
    subject = "University Portal — Password Reset Code"

    html_body = f"""
    <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 500px; margin: 0 auto;
                background: #1a1a2e; color: #e0e0e0; padding: 32px; border-radius: 12px;">
        <div style="text-align: center; margin-bottom: 24px;">
            <span style="font-size: 36px;">🔐</span>
            <h2 style="color: #00d4ff; margin: 8px 0;">Password Reset</h2>
        </div>
        <p>You requested a password reset for your University Portal account.</p>
        <p>Your verification code is:</p>
        <div style="text-align: center; margin: 24px 0;">
            <span style="font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #39ff14;
                         background: #16213e; padding: 12px 24px; border-radius: 8px;
                         border: 2px solid #00d4ff;">{code}</span>
        </div>
        <p style="color: #9ca3b8; font-size: 13px;">
            This code expires in <strong>10 minutes</strong>.<br>
            If you did not request this reset, please ignore this email.
        </p>
        <hr style="border: 1px solid #2a2a4a; margin: 24px 0;">
        <p style="color: #6c7293; font-size: 11px; text-align: center;">
            University Portal — Secure Academic Management System
        </p>
    </div>
    """

    text_body = f"""
University Portal — Password Reset

Your verification code is: {code}

This code expires in 10 minutes.
If you did not request this reset, please ignore this email.
    """

    return _send_email(email, subject, html_body, text_body)


def send_registration_code(email, code, username):
    """
    Send an email verification code for new account registration (Email MFA).
    Returns (sent_via_email: bool, error: str|None).
    """
    subject = "University Portal — Verify Your Email Address"

    html_body = f"""
    <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 500px; margin: 0 auto;
                background: #1a1a2e; color: #e0e0e0; padding: 32px; border-radius: 12px;">
        <div style="text-align: center; margin-bottom: 24px;">
            <span style="font-size: 36px;">🎓</span>
            <h2 style="color: #00d4ff; margin: 8px 0;">Welcome to University Portal</h2>
        </div>
        <p>Hello <strong>{username}</strong>,</p>
        <p>Thank you for registering. To verify your email address, please enter the following code:</p>
        <div style="text-align: center; margin: 24px 0;">
            <span style="font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #39ff14;
                         background: #16213e; padding: 12px 24px; border-radius: 8px;
                         border: 2px solid #00d4ff;">{code}</span>
        </div>
        <p style="color: #9ca3b8; font-size: 13px;">
            This code expires in <strong>10 minutes</strong>.<br>
            After verification, your account will await administrator approval before you can sign in.
        </p>
        <hr style="border: 1px solid #2a2a4a; margin: 24px 0;">
        <p style="color: #6c7293; font-size: 11px; text-align: center;">
            University Portal — Secure Academic Management System
        </p>
    </div>
    """

    text_body = f"""
University Portal — Email Verification

Hello {username},

Your verification code is: {code}

This code expires in 10 minutes.
After verification, your account will await administrator approval.
    """

    return _send_email(email, subject, html_body, text_body)


def send_change_password_code(email, code, username):
    """
    Send a verification code for password change (authenticated users).
    Returns (sent_via_email: bool, error: str|None).
    """
    subject = "University Portal — Password Change Verification"

    html_body = f"""
    <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 500px; margin: 0 auto;
                background: #1a1a2e; color: #e0e0e0; padding: 32px; border-radius: 12px;">
        <div style="text-align: center; margin-bottom: 24px;">
            <span style="font-size: 36px;">🔑</span>
            <h2 style="color: #00d4ff; margin: 8px 0;">Password Change Request</h2>
        </div>
        <p>Hello <strong>{username}</strong>,</p>
        <p>You requested to change your password. Please enter the following verification code to confirm:</p>
        <div style="text-align: center; margin: 24px 0;">
            <span style="font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #39ff14;
                         background: #16213e; padding: 12px 24px; border-radius: 8px;
                         border: 2px solid #00d4ff;">{code}</span>
        </div>
        <p style="color: #9ca3b8; font-size: 13px;">
            This code expires in <strong>10 minutes</strong>.<br>
            If you did not request this change, please secure your account immediately.
        </p>
        <hr style="border: 1px solid #2a2a4a; margin: 24px 0;">
        <p style="color: #6c7293; font-size: 11px; text-align: center;">
            University Portal — Secure Academic Management System
        </p>
    </div>
    """

    text_body = f"""
University Portal — Password Change Verification

Hello {username},

Your verification code is: {code}

This code expires in 10 minutes.
If you did not request this change, please secure your account immediately.
    """

    return _send_email(email, subject, html_body, text_body)
