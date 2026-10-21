import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch
from types import SimpleNamespace

import httpx
import pytest
from fastapi import HTTPException

from app.core.config import settings
from app.services.file_antivirus import FileAntivirus, private_engine_host
from app.modules.threat_intel.web_risk import query_web_risk
from app.services.orchestrator import AnalysisOrchestrator


@pytest.fixture
def anyio_backend():
    return 'asyncio'


@pytest.mark.parametrize('host,allowed', [
    ('127.0.0.1', True), ('10.0.0.2', True), ('clamav.internal', False),
    ('8.8.8.8', False), ('evil.example', False), ('https://engine.internal/', False),
])
def test_engine_private_only(host, allowed):
    assert private_engine_host(host) is allowed


@pytest.mark.anyio
@pytest.mark.parametrize('reply,status', [
    (b'stream: OK\x00', 'no_detection'),
    (b'stream: Synthetic.Test.Signature FOUND\x00', 'detected'),
    (b'stream: Heuristics.Limits.Exceeded.MaxScanSize FOUND\x00', 'incomplete'),
    (b'stream: Heuristics.Encrypted.Zip FOUND\x00', 'incomplete'),
    (b'stream: broken ERROR\x00', 'unavailable'),
])
async def test_clamd_stream_protocol(monkeypatch, reply, status):
    # Protocol fixture, NOT a real antivirus verdict. Never claim an engine test.
    captured = bytearray()
    async def handle(reader, writer):
        command = await reader.readuntil(b'\x00')
        if command == b'zVERSION\x00':
            date = datetime.now(timezone.utc).strftime('%a %b %d %H:%M:%S %Y')
            writer.write(f'ClamAV 1.4/123/{date}\x00'.encode())
        else:
            assert command == b'zINSTREAM\x00'
            while True:
                size = int.from_bytes(await reader.readexactly(4), 'big')
                if not size:
                    break
                captured.extend(await reader.readexactly(size))
            writer.write(reply)
        await writer.drain()
        writer.close()
        await writer.wait_closed()
    server = await asyncio.start_server(handle, '127.0.0.1', 0)
    monkeypatch.setattr(settings, 'CLAMAV_HOST', '127.0.0.1')
    monkeypatch.setattr(settings, 'CLAMAV_PORT', server.sockets[0].getsockname()[1])
    try:
        result = await FileAntivirus().scan(b'synthetic document bytes')
        assert result['status'] == status
        assert captured == b'synthetic document bytes'
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.anyio
async def test_stale_signatures_never_report_clean(monkeypatch):
    monkeypatch.setattr(settings, 'CLAMAV_HOST', '127.0.0.1')
    engine = FileAntivirus()
    engine._exchange = AsyncMock(return_value='ClamAV 1.4/123/Mon Jan 01 00:00:00 2024')
    assert (await engine.scan(b'document'))['status'] == 'stale_signatures'
    engine._exchange.assert_awaited_once()


@pytest.mark.anyio
async def test_truncated_zip_never_reports_clean(monkeypatch):
    monkeypatch.setattr(settings, 'CLAMAV_HOST', '127.0.0.1')
    engine = FileAntivirus()
    engine._exchange = AsyncMock()
    result = await engine.scan(b'PK\x03\x04truncated synthetic ZIP')
    assert result['status'] == 'incomplete' and not result['available']
    engine._exchange.assert_not_awaited()


@pytest.mark.anyio
async def test_file_failure_returns_no_analysis(monkeypatch):
    from app.services.file_antivirus import file_antivirus
    monkeypatch.setattr(file_antivirus, 'scan', AsyncMock(return_value={'available': False}))
    with pytest.raises(HTTPException) as exc:
        await AnalysisOrchestrator().analyze_file(b'data', 'a.txt', 'text/plain')
    assert exc.value.status_code == 503


@pytest.mark.anyio
async def test_file_detection_is_critical_and_never_submitted(monkeypatch):
    from app.services.file_antivirus import file_antivirus
    monkeypatch.setattr(file_antivirus, 'scan', AsyncMock(return_value={
        'provider': 'clamav', 'available': True, 'status': 'detected',
    }))
    orchestrator = AnalysisOrchestrator()
    orchestrator._threat_intel = SimpleNamespace(query_all=AsyncMock())
    monkeypatch.setattr(orchestrator, '_record', lambda *args: None)
    result = await orchestrator.analyze_file(b'fixture', 'example.txt', 'text/plain')
    assert result.risk_score.total == 100
    assert result.risk_score.level.value == 'critical'
    assert result.metadata['antivirus']['status'] == 'detected'
    orchestrator._threat_intel.query_all.assert_not_awaited()


@pytest.mark.anyio
@pytest.mark.parametrize('available,malicious', [(False, False), (True, True)])
async def test_url_reputation_required_and_detection_not_diluted(monkeypatch, available, malicious):
    import app.services.orchestrator as module
    monkeypatch.setattr(module, 'normalize_public_http_url', lambda url: (url, None))
    monkeypatch.setattr('app.modules.threat_intel.web_risk.query_web_risk', AsyncMock(return_value={
        'provider': 'google_web_risk', 'available': available,
        'data': {'score': 100 if malicious else 0, 'is_malicious': malicious},
    }))
    orchestrator = AnalysisOrchestrator()
    for name in ['_url_analyzer', '_header_analyzer', '_content_analyzer']:
        setattr(orchestrator, name, SimpleNamespace(
            analyze_url=AsyncMock(return_value={'score': 0}),
            analyze_headers=AsyncMock(return_value={'score': 0}),
            analyze_content=AsyncMock(return_value={'score': 0}),
        ))
    monkeypatch.setattr(module, 'safe_http_get', AsyncMock(return_value=SimpleNamespace(text='')))
    monkeypatch.setattr(orchestrator, '_record', lambda *args: None)
    if not available:
        with pytest.raises(HTTPException) as exc:
            await orchestrator.analyze_url('https://example.com/')
        assert exc.value.status_code == 503
    else:
        result = await orchestrator.analyze_url('https://example.com/')
        assert result.risk_score.total == 100
        assert result.risk_score.level.value == 'critical'


@pytest.mark.anyio
@pytest.mark.parametrize('status,payload,available,malicious', [
    (200, {}, True, False),
    (200, {'threat': {'threatTypes': ['SOCIAL_ENGINEERING']}}, True, True),
    (429, {}, False, False), (403, {}, False, False),
    (200, {'threat': 'bad'}, False, False),
    (200, {'error': {'message': 'synthetic provider error'}}, False, False),
    (200, {'threat': {}}, False, False),
    (200, {'threat': {'threatTypes': ['UNKNOWN_TYPE']}}, False, False),
])
async def test_web_risk_lookup_contract(monkeypatch, status, payload, available, malicious):
    monkeypatch.setattr(settings, 'GOOGLE_WEB_RISK_API_KEY', 'synthetic-only')
    def handle(request):
        assert str(request.url).startswith('https://webrisk.googleapis.com/v1/uris:search?')
        assert request.headers['x-goog-api-key'] == 'synthetic-only'
        assert 'synthetic-only' not in str(request.url)
        assert request.url.params.get_list('threatTypes') == ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE']
        return httpx.Response(status, json=payload)
    original_client = httpx.AsyncClient
    with patch('app.modules.threat_intel.web_risk.httpx.AsyncClient',
               side_effect=lambda **kw: original_client(transport=httpx.MockTransport(handle), **kw)):
        result = await query_web_risk('https://example.com/')
    assert result['available'] is available
    assert result['data'].get('is_malicious', False) is malicious
