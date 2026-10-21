"""Staging-only supervisor for the pinned Hostinger SSH tunnel and API.

Render secret file: /etc/secrets/guardiaflow_clamav_ssh. Never print its contents.
No change to the production start command.
"""
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import signal

STAGING_SERVICE = 'srv-db9ohdtg1s2s739fh5og'
HOST_KEY = 'srv2078699.hstgr.cloud ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICtV3EDrCj9hIaXw1BcswZfLletkWKyaSlXkdj9QE8e7\n'


def engine_ready():
    try:
        with socket.create_connection(('127.0.0.1', 3310), timeout=1) as client:
            client.sendall(b'zPING\x00')
            return client.recv(32) == b'PONG\x00'
    except OSError:
        return False


def stop(child):
    if child is not None and child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()


def main():
    if os.environ.get('RENDER_SERVICE_ID') != STAGING_SERVICE:
        raise SystemExit('Refusing to run outside the approved staging service.')
    if not shutil.which('ssh'):
        raise SystemExit('SSH client unavailable; staging was not started.')
    source = Path('/etc/secrets/guardiaflow_clamav_ssh')
    if not source.is_file():
        raise SystemExit('Staging SSH secret file missing.')
    tunnel = api = None
    def interrupted(_signum, _frame):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    with tempfile.TemporaryDirectory(prefix='gf-staging-ssh-') as directory:
        folder = Path(directory)
        key = folder / 'identity'
        key.write_bytes(source.read_bytes())
        key.chmod(0o600)
        hosts = folder / 'known_hosts'
        hosts.write_text(HOST_KEY)
        try:
            tunnel = subprocess.Popen([
                'ssh', '-F', '/dev/null', '-N', '-T', '-i', str(key),
                '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                '-o', 'StrictHostKeyChecking=yes',
                '-o', f'UserKnownHostsFile={hosts}',
                '-o', 'ExitOnForwardFailure=yes', '-o', 'ConnectTimeout=15',
                '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=2',
                '-L', '127.0.0.1:3310:127.0.0.1:3310',
                'gfclamav-stage@srv2078699.hstgr.cloud',
            ], stdin=subprocess.DEVNULL)
            deadline = time.monotonic() + 30
            while not engine_ready():
                if tunnel.poll() is not None or time.monotonic() >= deadline:
                    raise SystemExit('Private antivirus tunnel unavailable; API not started.')
                time.sleep(0.25)
            env = dict(os.environ, CLAMAV_HOST='127.0.0.1', CLAMAV_PORT='3310')
            api = subprocess.Popen([
                sys.executable, '-m', 'uvicorn', 'app.main:app', '--host', '0.0.0.0',
                '--port', os.environ.get('PORT', '8000'), '--workers', '1',
            ], env=env)
            while api.poll() is None:
                if tunnel.poll() is not None:
                    raise SystemExit('Private tunnel stopped; stopping staging API.')
                time.sleep(0.25)
            return api.returncode
        finally:
            stop(api)
            stop(tunnel)


if __name__ == '__main__':
    sys.exit(main())
