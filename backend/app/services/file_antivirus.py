"""Bounded INSTREAM scanning against an operator-configured private ClamAV.

Files stay in memory; never execute, unpack, or submit them to public services.
"""
import asyncio
import ipaddress
import io
import socket
import struct
import zipfile
from datetime import datetime, timezone

from app.core.config import settings


def private_engine_host(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host)
        return address.is_loopback or any(address in net for net in (
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16'),
        ) if address.version == net.version)
    except ValueError:
        return False


class FileAntivirus:
    def __init__(self):
        self._slots = asyncio.Semaphore(2)

    async def _exchange(self, command: bytes, content: bytes | None = None, *, host: str) -> str:
        reader, writer = await asyncio.open_connection(
            host, settings.CLAMAV_PORT, limit=4096,
        )
        try:
            writer.write(command)
            await writer.drain()
            if content is not None:
                for offset in range(0, len(content), 65536):
                    chunk = content[offset:offset + 65536]
                    writer.write(struct.pack('!I', len(chunk)) + chunk)
                    await writer.drain()
                writer.write(struct.pack('!I', 0))
                await writer.drain()
            reply = await reader.readuntil(b'\x00')
            return reply[:-1].decode('ascii', errors='strict')
        finally:
            writer.close()
            await writer.wait_closed()

    async def scan(self, content: bytes) -> dict:
        result = {'provider': 'clamav', 'status': 'unavailable', 'available': False}
        if not settings.CLAMAV_HOST:
            return result
        if not content or len(content) > 10 * 1024 * 1024:
            return {**result, 'status': 'incomplete'}
        # ClamAV can optimize away an oversized benign ZIP member and return
        # OK even with AlertExceedsMax. Enforce our contract before scanning.
        is_zip = zipfile.is_zipfile(io.BytesIO(content))
        if content.startswith((b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08')) and not is_zip:
            return {**result, 'status': 'incomplete'}
        if is_zip:
            try:
                with zipfile.ZipFile(io.BytesIO(content)) as archive:
                    members = archive.infolist()
                    if (len(members) > 500
                            or sum(m.file_size for m in members) > 25 * 1024 * 1024
                            or any(m.file_size > 10 * 1024 * 1024 or m.flag_bits & 1 for m in members)):
                        return {**result, 'status': 'incomplete'}
            except (ValueError, OSError, zipfile.BadZipFile):
                return {**result, 'status': 'incomplete'}
        try:
            # Client deadline precedes clamd MaxScanTime=20000 ms. Never
            # accept an OK that may follow a daemon-side scan-time limit.
            async with asyncio.timeout(15):
                async with self._slots:
                    addresses = await asyncio.get_running_loop().getaddrinfo(
                        settings.CLAMAV_HOST, settings.CLAMAV_PORT, type=socket.SOCK_STREAM)
                    ips = [address[4][0] for address in addresses]
                    if not ips or not all(private_engine_host(ip) for ip in ips):
                        return result
                    # Pin the resolved private address for VERSION and scanning.
                    host = ips[0]
                    version = await self._exchange(b'zVERSION\x00', host=host)
                    # Refuse stale/unknown signatures, including a stale worker.
                    stamp = datetime.strptime(version.rsplit('/', 1)[1], '%a %b %d %H:%M:%S %Y').replace(tzinfo=timezone.utc)
                    age = (datetime.now(timezone.utc) - stamp).total_seconds()
                    if not 0 <= age <= 72 * 3600:
                        return {**result, 'status': 'stale_signatures'}
                    reply = await self._exchange(b'zINSTREAM\x00', content, host=host)
            if reply == 'stream: OK':
                return {**result, 'status': 'no_detection', 'available': True}
            if reply.startswith('stream: ') and reply.endswith(' FOUND'):
                signature = reply[len('stream: '):-len(' FOUND')]
                if signature.startswith(('Heuristics.Limits.', 'Heuristics.Encrypted.')):
                    return {**result, 'status': 'incomplete'}
                return {**result, 'status': 'detected', 'available': True, 'signature': signature}
        except (OSError, TimeoutError, ValueError, IndexError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass
        return result


file_antivirus = FileAntivirus()
