"""
Security Logger - Registro de eventos de seguridad
"""
from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Optional

# Crear directorio de logs
LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

# Logger principal de seguridad
security_logger = logging.getLogger("ai_sentinel.security")
security_logger.setLevel(logging.INFO)

# File handler
file_handler = logging.FileHandler(os.path.join(LOG_DIR, "security.log"))
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(
    logging.Formatter("%(asctime)s | %(levelname)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
)
security_logger.addHandler(file_handler)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.WARNING)
console_handler.setFormatter(
    logging.Formatter("[SECURITY] %(levelname)s: %(message)s")
)
security_logger.addHandler(console_handler)

# Audit logger (eventos criticos)
audit_logger = logging.getLogger("ai_sentinel.audit")
audit_logger.setLevel(logging.INFO)

audit_handler = logging.FileHandler(os.path.join(LOG_DIR, "audit.log"))
audit_handler.setFormatter(
    logging.Formatter("%(asctime)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
)
audit_logger.addHandler(audit_handler)


def log_auth_event(event_type: str, username: str, ip: str, success: bool, detail: str = ""):
    level = logging.INFO if success else logging.WARNING
    msg = f"AUTH | {event_type} | user={username} | ip={ip} | success={success}"
    if detail:
        msg += f" | {detail}"
    security_logger.log(level, msg)
    audit_logger.info(msg)


def log_rate_limit(ip: str, endpoint: str, count: int, limit: int):
    security_logger.warning(f"RATE_LIMIT | ip={ip} | endpoint={endpoint} | count={count}/{limit}")


def log_blocked_ip(ip: str, reason: str, duration: int):
    security_logger.warning(f"IP_BLOCKED | ip={ip} | reason={reason} | duration={duration}s")
    audit_logger.info(f"IP_BLOCKED | ip={ip} | reason={reason} | duration={duration}s")


def log_malicious_request(ip: str, url: str, pattern: str):
    security_logger.critical(f"MALICIOUS | ip={ip} | url={url} | pattern={pattern}")
    audit_logger.info(f"MALICIOUS | ip={ip} | url={url} | pattern={pattern}")


def log_analysis_event(analysis_type: str, target: str, risk_level: str, ip: str):
    security_logger.info(f"ANALYSIS | type={analysis_type} | target={target} | risk={risk_level} | ip={ip}")


def log_threat_detected(threat_type: str, target: str, score: float, ip: str):
    if score >= 75:
        security_logger.critical(f"THREAT_CRITICAL | type={threat_type} | target={target} | score={score} | ip={ip}")
    elif score >= 50:
        security_logger.warning(f"THREAT_HIGH | type={threat_type} | target={target} | score={score} | ip={ip}")
    else:
        security_logger.info(f"THREAT | type={threat_type} | target={target} | score={score} | ip={ip}")
