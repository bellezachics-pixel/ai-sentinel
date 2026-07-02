from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


def normalize_public_http_url(raw_url: str) -> tuple[str | None, dict | None]:
    """Return a normalized public HTTP(S) URL or a finding explaining why it is blocked."""
    url = (raw_url or "").strip()
    if not url:
        return None, _finding("url vacia", "No se recibio una URL valida.")

    if "://" not in url:
        url = f"https://{url}"

    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return None, _finding(
            "esquema bloqueado",
            "Solo se permiten URLs http o https para analisis de red.",
        )

    hostname = parsed.hostname
    if not hostname:
        return None, _finding("host invalido", "No se pudo identificar el host de la URL.")

    if hostname.lower() in {"localhost", "localhost.localdomain"}:
        return None, _finding(
            "host local bloqueado",
            "Se bloqueo el acceso a localhost para prevenir SSRF.",
        )

    try:
        addresses = {
            result[4][0]
            for result in socket.getaddrinfo(hostname, parsed.port, type=socket.SOCK_STREAM)
        }
    except socket.gaierror:
        return None, _finding(
            "dns no resuelto",
            "No se pudo resolver el dominio; se omitieron conexiones externas.",
            severity="medium",
        )

    for address in addresses:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return None, _finding("ip invalida", f"DNS devolvio una IP invalida: {address}")
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return None, _finding(
                "ip privada bloqueada",
                f"Se bloqueo la conexion a {address} para prevenir SSRF.",
            )

    return url, None


def _finding(finding_type: str, description: str, severity: str = "high") -> dict:
    return {
        "type": finding_type,
        "severity": severity,
        "description": description,
        "category": "network_safety",
    }
