import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Tuple, Optional


def get_smtp_config_from_env() -> dict:
    config = {}
    if os.getenv("SMTP_SERVER"):
        config["server"] = os.environ["SMTP_SERVER"]
    if os.getenv("SMTP_PORT"):
        config["port"] = int(os.environ["SMTP_PORT"])
    if os.getenv("SMTP_EMAIL"):
        config["email"] = os.environ["SMTP_EMAIL"]
    if os.getenv("SMTP_PASSWORD"):
        config["password"] = os.environ["SMTP_PASSWORD"]
    return config


def _smtp_send(
    smtp_server: str,
    smtp_port: int,
    sender_email: str,
    sender_password: str,
    receiver_email: str,
    subject: str,
    body: str,
) -> Tuple[bool, str]:
    try:
        msg = MIMEMultipart()
        msg["From"] = sender_email
        msg["To"] = receiver_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        server = smtplib.SMTP(smtp_server, int(smtp_port), timeout=30)
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)
        server.quit()
        return True, f"Email sent to {receiver_email}."
    except smtplib.SMTPAuthenticationError:
        return False, "SMTP authentication failed. Check email and app password."
    except smtplib.SMTPException as e:
        return False, f"SMTP error: {str(e)}"
    except Exception as e:
        return False, f"Email sending failed: {str(e)}"


def send_key_email(
    smtp_server: str,
    smtp_port: int,
    sender_email: str,
    sender_password: str,
    receiver_email: str,
    key_material: str,
    cipher_mode: str = "",
) -> Tuple[bool, str]:
    """Send ONLY the cryptographic key on a dedicated channel."""
    body = (
        "MASTER CRYPTO LAB — KEY CHANNEL\n"
        + "=" * 67 + "\n"
        + "WARNING: This message contains SECRET KEY MATERIAL.\n"
        + "Transmit only over a trusted channel. Do not forward.\n\n"
        + f"CIPHER MODE: {cipher_mode or 'N/A'}\n\n"
        + "KEY:\n"
        + f"{key_material}\n"
        + "=" * 67 + "\n"
        + "Use this key only with the matching ciphertext received on a SEPARATE channel.\n"
    )
    return _smtp_send(
        smtp_server, smtp_port, sender_email, sender_password,
        receiver_email,
        subject="[MCL] Key material — out-of-band channel",
        body=body,
    )


def send_ciphertext_email(
    smtp_server: str,
    smtp_port: int,
    sender_email: str,
    sender_password: str,
    receiver_email: str,
    ciphertext: str,
    license_code: str = "",
    cipher_mode: str = "",
) -> Tuple[bool, str]:
    """Send ONLY ciphertext (no key) — zero-knowledge style."""
    body = (
        "MASTER CRYPTO LAB — CIPHERTEXT CHANNEL\n"
        + "=" * 67 + "\n"
        + "SECURITY NOTICE: The Master Key is NOT included in this email.\n"
        + "Decrypt only with the key received on a separate secure channel.\n\n"
        + f"CIPHER MODE: {cipher_mode or 'N/A'}\n\n"
        + "CIPHERTEXT:\n"
        + f"{ciphertext}\n\n"
    )
    if license_code:
        body += f"LICENSE CODE:\n{license_code}\n"
    body += "=" * 67 + "\n"
    return _smtp_send(
        smtp_server, smtp_port, sender_email, sender_password,
        receiver_email,
        subject="[MCL] Encrypted package — ciphertext only",
        body=body,
    )


def send_zero_knowledge_email(
    smtp_server: str,
    smtp_port: int,
    sender_email: str,
    sender_password: str,
    receiver_email: str,
    ciphertext: str,
    license_code: str,
) -> Tuple[bool, str]:
    """Backward-compatible wrapper → ciphertext-only channel."""
    return send_ciphertext_email(
        smtp_server, smtp_port, sender_email, sender_password,
        receiver_email, ciphertext, license_code=license_code,
    )
