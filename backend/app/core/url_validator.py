"""
Validación segura de URLs para prevenir SSRF.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse


PRIVATE_IP_PATTERNS = [
    re.compile(r"^127\."),
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2[0-9]|3[01])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^0\."),
    re.compile(r"^169\.254\."),
    re.compile(r"^::1$"),
    re.compile(r"^fc00:", re.I),
    re.compile(r"^fe80:", re.I),
]

BLOCKED_SCHEMES = {"file", "ftp", "gopher", "telnet", "ldap", "smb"}
ALLOWED_SCHEMES = {"http", "https"}


def is_private_ip(host: str) -> bool:
    """Check if hostname/IP resolves to a private/internal address."""
    host = host.lower().strip()
    if host in ("localhost", "localhost.localdomain"):
        return True
    for pattern in PRIVATE_IP_PATTERNS:
        if pattern.match(host):
            return True
    try:
        addr = ipaddress.ip_address(host)
        return addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local
    except ValueError:
        pass
    return False


def validate_url(url: str, allow_private: bool = False) -> str:
    """
    Valida que una URL sea segura para ser fetchada por el backend.
    Retorna la URL normalizada o lanza ValueError.
    """
    url = url.strip()
    if not url:
        raise ValueError("URL vacia")

    parsed = urlparse(url)

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise ValueError(f"Esquema no permitido: {parsed.scheme}")

    if not parsed.hostname:
        raise ValueError("URL sin hostname")

    hostname = parsed.hostname.lower()

    if not allow_private and is_private_ip(hostname):
        raise ValueError("Direccion IP privada o localhost no permitida")

    return url
