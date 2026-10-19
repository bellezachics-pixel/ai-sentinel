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


# Maximo de redirecciones seguidas en fetch con validacion anti-SSRF.
MAX_SAFE_REDIRECTS = 5


async def safe_http_get(url: str, timeout: float = 10.0, max_redirects: int = MAX_SAFE_REDIRECTS):
    """
    GET HTTP(S) con redirecciones validadas SALTO A SALTO.

    Cada destino intermedio pasa por normalize_public_http_url antes de
    conectar: una redireccion hacia una IP privada, de metadatos cloud o
    local es rechazada antes de la conexion. Cierra el vector SSRF por
    redireccion (servidor publico que redirige hacia la red interna).
    """
    import httpx

    current = url
    async with httpx.AsyncClient(
        timeout=timeout, follow_redirects=False, verify=True
    ) as client:
        for _ in range(max_redirects + 1):
            validated, finding = normalize_public_http_url(current)
            if not validated:
                raise ValueError(
                    f"Redireccion bloqueada por seguridad: "
                    f"{(finding or {}).get('description', 'destino no permitido')}"
                )
            resp = await client.get(validated)
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location")
                if not location:
                    return resp
                from urllib.parse import urljoin

                current = urljoin(validated, location)
                continue
            return resp
    raise ValueError(f"Demasiadas redirecciones (mas de {max_redirects})")


def validate_public_network_target(target: str) -> str:
    """
    Validate that a network-scan target is safe to connect to (SSRF guard).

    Accepts a hostname, IP address, or http(s) URL. Raises ValueError if the
    target is private, loopback, link-local (incl. cloud metadata
    169.254.169.254), reserved, multicast, unspecified, or resolves to any
    such address. Returns the normalized hostname/IP on success.
    """
    raw = (target or "").strip()
    if not raw:
        raise ValueError("Objetivo de red requerido")

    if "://" in raw:
        parsed = urlparse(raw)
        host = parsed.hostname
    else:
        # Strip any path and port (IPv6 literals in brackets handled below)
        host = raw.split("/", 1)[0]
        if host.startswith("[") and "]" in host:
            host = host[1:host.index("]")]
        elif ":" in host:
            host = host.rsplit(":", 1)[0]

    host = (host or "").strip().lower()
    if not host:
        raise ValueError("Objetivo de red invalido")

    if host in {"localhost", "localhost.localdomain"}:
        raise ValueError(
            "Se bloqueo el acceso a localhost para prevenir SSRF."
        )

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None

    if ip is not None:
        _reject_non_public_ip(ip)
        return host

    # Hostname: resolve and verify every resolved address is public
    try:
        addresses = {
            result[4][0]
            for result in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        }
    except socket.gaierror:
        raise ValueError(f"No se pudo resolver el objetivo: {host}")

    if not addresses:
        raise ValueError(f"No se pudo resolver el objetivo: {host}")

    for address in addresses:
        try:
            resolved = ipaddress.ip_address(address)
        except ValueError:
            raise ValueError(f"DNS devolvio una IP invalida: {address}")
        _reject_non_public_ip(resolved)

    return host


# Cloud metadata + CGNAT ranges not covered by is_private on all Python versions
_EXTRA_BLOCKED_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),   # link-local / cloud metadata
    ipaddress.ip_network("100.64.0.0/10"),    # CGNAT (RFC 6598)
]


def _reject_non_public_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address):
    blocked = (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or any(ip in net for net in _EXTRA_BLOCKED_NETWORKS)
    )
    if blocked:
        raise ValueError(
            f"Se bloqueo la conexion a {ip} (direccion privada, reservada "
            f"o de metadatos) para prevenir SSRF."
        )


def _finding(finding_type: str, description: str, severity: str = "high") -> dict:
    return {
        "type": finding_type,
        "severity": severity,
        "description": description,
        "category": "network_safety",
    }
