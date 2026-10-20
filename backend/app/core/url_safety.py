from __future__ import annotations

import asyncio
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

    # urlparse puede lanzar ValueError con IPv6 mal formada (ej. "https://[::1")
    try:
        parsed = urlparse(url)
    except ValueError:
        return None, _finding("url invalida", "La URL tiene un formato invalido.")

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

    # Decision segura ante cualquier error de parsing/resolucion
    # (REVISION-GUARDIA-FLOW #17, residual): puerto fuera de rango
    # (parsed.port lanza ValueError), dominio demasiado largo, errores de
    # codificacion Unicode o fallos de DNS. Nada de esto debe dar 500.
    try:
        addresses = {
            result[4][0]
            for result in socket.getaddrinfo(hostname, parsed.port, type=socket.SOCK_STREAM)
        }
    except (socket.gaierror, socket.herror, UnicodeError, ValueError, OSError):
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
            # CGNAT (100.64/10): is_private es False en varias versiones de
            # Python; misma red extra que ya bloquea _reject_non_public_ip.
            or any(ip in net for net in _EXTRA_BLOCKED_NETWORKS)
        ):
            return None, _finding(
                "ip privada bloqueada",
                f"Se bloqueo la conexion a {address} para prevenir SSRF.",
            )

    return url, None


# Maximo de redirecciones seguidas en fetch con validacion anti-SSRF.
MAX_SAFE_REDIRECTS = 5

# Limite de bytes DURANTE la descarga (contenido descomprimido): corta la
# transferencia al llegar, no despues de descargar todo.
MAX_DOWNLOAD_BYTES = 2_000_000


async def _read_limited(response, max_bytes: int = MAX_DOWNLOAD_BYTES) -> bytes:
    """Lee el cuerpo de una respuesta en streaming, cortando a max_bytes.

    httpx descarga y descomprime chunk a chunk: un servidor malicioso no
    puede inflar la memoria mandando cientos de MB (el recorte posterior
    de 'resp.text[:2MB]' limitaba el trabajo de regex, pero no la red/RAM).
    """
    chunks: list[bytes] = []
    total = 0
    async for chunk in response.aiter_bytes():
        if total >= max_bytes:
            break
        take = chunk[: max_bytes - total]
        chunks.append(take)
        total += len(take)
    return b"".join(chunks)


async def safe_http_get(url: str, timeout: float = 10.0, max_redirects: int = MAX_SAFE_REDIRECTS):
    """
    GET HTTP(S) con redirecciones validadas SALTO A SALTO.

    Cada destino intermedio pasa por normalize_public_http_url antes de
    conectar: una redireccion hacia una IP privada, de metadatos cloud o
    local es rechazada antes de la conexion. Cierra el vector SSRF por
    redireccion (servidor publico que redirige hacia la red interna).
    La descarga se corta a MAX_DOWNLOAD_BYTES durante la transferencia.
    """
    import httpx

    current = url
    async with httpx.AsyncClient(
        timeout=timeout, follow_redirects=False, verify=True
    ) as client:
        for _ in range(max_redirects + 1):
            # getaddrinfo es bloqueante: moverlo a un hilo para no congelar
            # el event loop durante la resolucion DNS.
            validated, finding = await asyncio.to_thread(normalize_public_http_url, current)
            if not validated:
                raise ValueError(
                    f"Redireccion bloqueada por seguridad: "
                    f"{(finding or {}).get('description', 'destino no permitido')}"
                )
            resp = await client.send(
                client.build_request("GET", validated), stream=True
            )
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location")
                await resp.aclose()
                if not location:
                    return resp
                from urllib.parse import urljoin

                current = urljoin(validated, location)
                continue
            body = await _read_limited(resp)
            await resp.aclose()
            return _BufferedResponse(resp, body)
    raise ValueError(f"Demasiadas redirecciones (mas de {max_redirects})")


class _BufferedResponse:
    """Compatibilidad minima con la interfaz de respuesta que usan los
    analizadores: status_code, headers y .text (decodificado) ya recortado
    al limite de descarga."""

    def __init__(self, response, body: bytes):
        self.status_code = response.status_code
        self.headers = response.headers
        self._text: str | None = None
        self._body = body

    @property
    def text(self) -> str:
        if self._text is None:
            enc = "utf-8"
            content_type = self.headers.get("content-type", "")
            for part in content_type.split(";"):
                part = part.strip()
                if part.lower().startswith("charset="):
                    enc = part.split("=", 1)[1].strip() or "utf-8"
            self._text = self._body.decode(enc, errors="replace")
        return self._text

    def json(self):
        import json as _json

        return _json.loads(self.text)

    def close(self):
        return None


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
        try:
            parsed = urlparse(raw)
        except ValueError:
            raise ValueError("Objetivo de red invalido")
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
    except (socket.gaierror, socket.herror, UnicodeError, OSError):
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
