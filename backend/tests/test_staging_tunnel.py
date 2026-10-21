"""Deployment guards; no credentials or external network required."""
import importlib.util
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

spec = importlib.util.spec_from_file_location(
    'staging_tunnel', Path(__file__).parents[1] / 'scripts/start_antivirus_staging.py')
tunnel = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tunnel)


def test_refuses_production_service(monkeypatch):
    monkeypatch.setenv('RENDER_SERVICE_ID', 'srv-production')
    with pytest.raises(SystemExit, match='outside the approved staging'):
        tunnel.main()


def test_missing_identity_does_not_start_process(monkeypatch):
    monkeypatch.setenv('RENDER_SERVICE_ID', tunnel.STAGING_SERVICE)
    with patch.object(tunnel.shutil, 'which', return_value='/usr/bin/ssh'), \
            patch.object(tunnel.Path, 'is_file', return_value=False), \
            patch.object(tunnel.subprocess, 'Popen') as spawn:
        with pytest.raises(SystemExit, match='secret file missing'):
            tunnel.main()
        spawn.assert_not_called()


def test_probe_requires_complete_pong():
    client = MagicMock()
    client.__enter__.return_value = client
    with patch.object(tunnel.socket, 'create_connection', return_value=client):
        client.recv.return_value = b'OK\x00'
        assert not tunnel.engine_ready()
        client.recv.return_value = b'PONG\x00'
        assert tunnel.engine_ready()


def test_tunnel_failure_stops_api(monkeypatch):
    monkeypatch.setenv('RENDER_SERVICE_ID', tunnel.STAGING_SERVICE)
    ssh, api = MagicMock(), MagicMock()
    ssh.poll.return_value = 255
    api.poll.return_value = None
    with patch.object(tunnel.shutil, 'which', return_value='/usr/bin/ssh'), \
            patch.object(tunnel.Path, 'is_file', return_value=True), \
            patch.object(tunnel.Path, 'read_bytes', return_value=b'synthetic-test-identity'), \
            patch.object(tunnel, 'engine_ready', return_value=True), \
            patch.object(tunnel.signal, 'signal'), \
            patch.object(tunnel.subprocess, 'Popen', side_effect=[ssh, api]) as spawn:
        with pytest.raises(SystemExit, match='tunnel stopped'):
            tunnel.main()
        api.terminate.assert_called_once()
        args = spawn.call_args_list[0].args[0]
        assert 'StrictHostKeyChecking=yes' in args
        assert '127.0.0.1:3310:127.0.0.1:3310' in args
