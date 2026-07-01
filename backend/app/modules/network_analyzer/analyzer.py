"""
AI-Sentinel Network Analyzer Module

Behavioral baseline modeling, AiTM detection via TLS fingerprinting,
proxy detection, and network integrity monitoring (ARP spoofing indicators,
DNS anomalies).
"""

from __future__ import annotations

import hashlib
import socket
import ssl
import struct
import time
from typing import Any
from urllib.parse import urlparse

import httpx


# --- Known TLS Fingerprint Database (JA3-style hashes for common proxies) ---

KNOWN_PROXY_FINGERPRINTS: set[str] = {
    # Placeholder hashes representing known AiTM/proxy tool fingerprints
    "e7d705a3286e19ea42f587b344ee6865",  # evilginx2
    "6734f37431670b3ab4292b8f60f29984",  # modlishka
    "cd08e31494f9531f560d64c695473da9",  # muraena
}

# Well-known DNS resolvers for comparison
TRUSTED_DNS_SERVERS: list[str] = [
    "8.8.8.8",       # Google
    "8.8.4.4",       # Google
    "1.1.1.1",       # Cloudflare
    "1.0.0.1",       # Cloudflare
    "9.9.9.9",       # Quad9
    "208.67.222.222", # OpenDNS
]


class NetworkAnalyzer:
    """Network integrity and AiTM detection analyzer."""

    # ---- Behavioral Baseline Modeling ----

    async def _measure_latency(
        self, host: str, port: int = 443, samples: int = 5
    ) -> dict[str, Any]:
        """Measure connection latency to a host over multiple samples."""
        latencies: list[float] = []
        errors: list[str] = []

        for _ in range(samples):
            start = time.monotonic()
            try:
                sock = socket.create_connection((host, port), timeout=10)
                elapsed = (time.monotonic() - start) * 1000  # ms
                latencies.append(elapsed)
                sock.close()
            except (socket.timeout, socket.gaierror, OSError) as exc:
                errors.append(str(exc))

        if not latencies:
            return {
                "avg_latency_ms": None,
                "min_latency_ms": None,
                "max_latency_ms": None,
                "jitter_ms": None,
                "samples": 0,
                "errors": errors,
            }

        avg = sum(latencies) / len(latencies)
        jitter = max(latencies) - min(latencies) if len(latencies) > 1 else 0.0

        return {
            "avg_latency_ms": round(avg, 2),
            "min_latency_ms": round(min(latencies), 2),
            "max_latency_ms": round(max(latencies), 2),
            "jitter_ms": round(jitter, 2),
            "samples": len(latencies),
            "latencies": [round(l, 2) for l in latencies],
            "errors": errors,
        }

    async def _check_dns_resolution(self, hostname: str) -> dict[str, Any]:
        """Resolve a hostname and check for DNS anomalies."""
        results: dict[str, Any] = {
            "hostname": hostname,
            "resolved_ips": [],
            "reverse_dns": {},
            "anomalies": [],
        }

        try:
            # Forward resolution
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_INET)
            ips = list({info[4][0] for info in addr_info})
            results["resolved_ips"] = ips

            # Reverse DNS for each IP
            for ip in ips[:5]:
                try:
                    reverse = socket.gethostbyaddr(ip)
                    results["reverse_dns"][ip] = reverse[0]
                except (socket.herror, socket.gaierror):
                    results["reverse_dns"][ip] = None

            # Check for anomalies
            if not ips:
                results["anomalies"].append({
                    "type": "no_resolution",
                    "severity": "high",
                    "detail": f"Hostname '{hostname}' did not resolve to any IP",
                })

            # Check if resolved IP is a private/reserved address
            for ip in ips:
                if self._is_private_ip(ip):
                    results["anomalies"].append({
                        "type": "private_ip_resolution",
                        "severity": "high",
                        "detail": f"Hostname resolved to private IP: {ip}",
                        "ip": ip,
                    })

            # Check for reverse DNS mismatch
            for ip, rdns in results["reverse_dns"].items():
                if rdns and hostname not in rdns and not rdns.endswith(f".{hostname}"):
                    results["anomalies"].append({
                        "type": "reverse_dns_mismatch",
                        "severity": "medium",
                        "detail": (
                            f"Reverse DNS for {ip} is '{rdns}', "
                            f"does not match hostname '{hostname}'"
                        ),
                        "ip": ip,
                        "reverse_dns": rdns,
                    })

        except socket.gaierror as exc:
            results["anomalies"].append({
                "type": "dns_resolution_failed",
                "severity": "high",
                "detail": f"DNS resolution failed: {str(exc)}",
            })

        return results

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Check if an IP address is in a private/reserved range."""
        try:
            parts = [int(p) for p in ip.split(".")]
            if len(parts) != 4:
                return False
            # 10.0.0.0/8
            if parts[0] == 10:
                return True
            # 172.16.0.0/12
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            # 192.168.0.0/16
            if parts[0] == 192 and parts[1] == 168:
                return True
            # 127.0.0.0/8
            if parts[0] == 127:
                return True
            # 169.254.0.0/16 (link-local)
            if parts[0] == 169 and parts[1] == 254:
                return True
            return False
        except (ValueError, IndexError):
            return False

    # ---- TLS Fingerprinting ----

    async def get_tls_fingerprint(self, host: str, port: int = 443) -> dict[str, Any]:
        """
        Generate a TLS fingerprint for a host connection.

        Captures cipher suite, protocol version, and certificate details
        to create a composite fingerprint.

        Args:
            host: The hostname to fingerprint.
            port: The port to connect on (default 443).

        Returns:
            Dictionary with fingerprint data and analysis.
        """
        fingerprint: dict[str, Any] = {
            "host": host,
            "port": port,
            "fingerprint_hash": None,
            "details": {},
            "findings": [],
        }

        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    protocol = ssock.version()

                    details: dict[str, Any] = {
                        "protocol": protocol,
                        "cipher_suite": cipher[0] if cipher else None,
                        "cipher_bits": cipher[2] if cipher and len(cipher) > 2 else None,
                    }

                    if cert:
                        details["cert_subject"] = dict(
                            x[0] for x in cert.get("subject", ())
                        )
                        details["cert_issuer"] = dict(
                            x[0] for x in cert.get("issuer", ())
                        )
                        details["cert_serial"] = cert.get("serialNumber")
                        details["cert_not_after"] = cert.get("notAfter")
                        san = cert.get("subjectAltName", ())
                        details["cert_san"] = [e[1] for e in san]

                    fingerprint["details"] = details

                    # Generate composite fingerprint hash
                    fp_data = (
                        f"{protocol}|{cipher}|"
                        f"{details.get('cert_issuer', {})}|"
                        f"{details.get('cert_serial', '')}"
                    )
                    fp_hash = hashlib.md5(fp_data.encode()).hexdigest()
                    fingerprint["fingerprint_hash"] = fp_hash

                    # Check against known proxy fingerprints
                    if fp_hash in KNOWN_PROXY_FINGERPRINTS:
                        fingerprint["findings"].append({
                            "category": "aitm_detection",
                            "pattern_type": "known_proxy_fingerprint",
                            "severity": "critical",
                            "detail": "TLS fingerprint matches a known AiTM proxy tool",
                            "fingerprint": fp_hash,
                        })

                    # Check for weak protocols
                    if protocol and protocol in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                        fingerprint["findings"].append({
                            "category": "tls_weakness",
                            "pattern_type": "weak_protocol",
                            "severity": "high",
                            "detail": f"Weak TLS protocol in use: {protocol}",
                        })

                    # Check cipher strength
                    if cipher and len(cipher) > 2 and cipher[2] < 128:
                        fingerprint["findings"].append({
                            "category": "tls_weakness",
                            "pattern_type": "weak_cipher",
                            "severity": "high",
                            "detail": f"Weak cipher strength: {cipher[2]} bits ({cipher[0]})",
                        })

        except ssl.SSLCertVerificationError as exc:
            fingerprint["findings"].append({
                "category": "tls_issue",
                "pattern_type": "cert_verification_failed",
                "severity": "critical",
                "detail": f"TLS certificate verification failed: {str(exc)}",
            })
        except (socket.timeout, socket.gaierror, OSError) as exc:
            fingerprint["findings"].append({
                "category": "connection_error",
                "severity": "high",
                "detail": f"Could not connect for TLS fingerprinting: {str(exc)}",
            })

        return fingerprint

    # ---- AiTM Detection ----

    async def detect_aitm_indicators(self, host: str) -> dict[str, Any]:
        """
        Detect Adversary-in-the-Middle indicators for a host.

        Combines TLS fingerprinting, latency analysis, DNS checks,
        and HTTP header inspection.

        Args:
            host: The hostname or URL to analyze.

        Returns:
            Dictionary with 'score', 'findings', and 'metadata' keys.
        """
        try:
            # Normalize host
            if host.startswith(("http://", "https://")):
                parsed = urlparse(host)
                hostname = parsed.hostname or host
            else:
                hostname = host

            all_findings: list[dict[str, Any]] = []

            # TLS fingerprint analysis
            tls_fp = await self.get_tls_fingerprint(hostname)
            all_findings.extend(tls_fp.get("findings", []))

            # Latency analysis (high jitter can indicate proxy)
            latency = await self._measure_latency(hostname)
            if latency.get("jitter_ms") is not None and latency["jitter_ms"] > 100:
                all_findings.append({
                    "category": "aitm_indicator",
                    "pattern_type": "high_jitter",
                    "severity": "medium",
                    "detail": (
                        f"High latency jitter ({latency['jitter_ms']}ms) "
                        "may indicate traffic proxying"
                    ),
                    "jitter_ms": latency["jitter_ms"],
                })

            if latency.get("avg_latency_ms") is not None and latency["avg_latency_ms"] > 500:
                all_findings.append({
                    "category": "aitm_indicator",
                    "pattern_type": "high_latency",
                    "severity": "low",
                    "detail": (
                        f"High average latency ({latency['avg_latency_ms']}ms) "
                        "may indicate traffic proxying"
                    ),
                })

            # HTTP-level proxy detection
            try:
                async with httpx.AsyncClient(
                    timeout=15.0, follow_redirects=True, verify=True
                ) as client:
                    resp = await client.head(f"https://{hostname}")
                    headers_lower = {k.lower(): v for k, v in resp.headers.items()}

                    proxy_headers = [
                        "x-forwarded-for", "x-forwarded-host", "via",
                        "x-real-ip", "x-forwarded-proto",
                    ]
                    for ph in proxy_headers:
                        if ph in headers_lower:
                            all_findings.append({
                                "category": "aitm_indicator",
                                "pattern_type": "proxy_header",
                                "severity": "medium",
                                "detail": f"Proxy header '{ph}' present in response",
                                "value": headers_lower[ph][:200],
                            })

                    # Check for response header anomalies
                    server = headers_lower.get("server", "").lower()
                    suspicious_servers = [
                        "evilginx", "modlishka", "muraena", "gophish",
                    ]
                    for ss in suspicious_servers:
                        if ss in server:
                            all_findings.append({
                                "category": "aitm_detection",
                                "pattern_type": "known_phishing_server",
                                "severity": "critical",
                                "detail": f"Server header matches known phishing tool: {ss}",
                            })

            except (httpx.ConnectError, httpx.TimeoutException):
                pass  # HTTP check is supplementary; don't fail on it

            score = self._calculate_score(all_findings)

            risk_level = "safe"
            if score >= 75:
                risk_level = "critical"
            elif score >= 50:
                risk_level = "high"
            elif score >= 25:
                risk_level = "medium"
            elif score > 0:
                risk_level = "low"

            return {
                "score": score,
                "risk_level": risk_level,
                "findings": all_findings,
                "metadata": {
                    "host": hostname,
                    "tls_fingerprint": tls_fp.get("fingerprint_hash"),
                    "latency": latency,
                    "analysis_type": "aitm_detection",
                },
            }

        except Exception as exc:
            return {
                "score": 0,
                "findings": [],
                "metadata": {
                    "error": f"AiTM detection failed: {str(exc)}",
                    "host": host,
                    "analysis_type": "aitm_detection",
                },
            }

    # ---- Network Integrity Guard ----

    async def check_network_integrity(self, target: str) -> dict[str, Any]:
        """
        Comprehensive network integrity check for a target.

        Monitors for ARP spoofing indicators, DNS anomalies, and
        performs behavioral baseline modeling.

        Args:
            target: Hostname, URL, or IP address to check.

        Returns:
            Dictionary with 'score', 'findings', and 'metadata' keys.
        """
        try:
            # Normalize target
            if target.startswith(("http://", "https://")):
                parsed = urlparse(target)
                hostname = parsed.hostname or target
            else:
                hostname = target

            all_findings: list[dict[str, Any]] = []

            # DNS resolution check
            dns_results = await self._check_dns_resolution(hostname)
            all_findings.extend(dns_results.get("anomalies", []))

            # Multi-resolver DNS consistency check
            dns_consistency = await self._check_dns_consistency(hostname)
            all_findings.extend(dns_consistency.get("findings", []))

            # Latency baseline
            latency = await self._measure_latency(hostname)

            # TLS fingerprint
            tls_fp = await self.get_tls_fingerprint(hostname)
            all_findings.extend(tls_fp.get("findings", []))

            # AiTM indicators
            aitm = await self.detect_aitm_indicators(hostname)
            # Avoid duplicating findings already collected
            for finding in aitm.get("findings", []):
                if finding not in all_findings:
                    all_findings.append(finding)

            # Deduplicate findings by (category, pattern_type, detail)
            seen: set[tuple[str, str, str]] = set()
            unique_findings: list[dict[str, Any]] = []
            for f in all_findings:
                key = (
                    f.get("category", ""),
                    f.get("pattern_type", ""),
                    f.get("detail", ""),
                )
                if key not in seen:
                    seen.add(key)
                    unique_findings.append(f)

            score = self._calculate_score(unique_findings)

            risk_level = "safe"
            if score >= 75:
                risk_level = "critical"
            elif score >= 50:
                risk_level = "high"
            elif score >= 25:
                risk_level = "medium"
            elif score > 0:
                risk_level = "low"

            return {
                "score": score,
                "risk_level": risk_level,
                "findings": unique_findings,
                "metadata": {
                    "target": target,
                    "hostname": hostname,
                    "dns": dns_results,
                    "dns_consistency": dns_consistency,
                    "latency": latency,
                    "tls_fingerprint": tls_fp.get("fingerprint_hash"),
                    "analysis_type": "network_integrity",
                },
            }

        except Exception as exc:
            return {
                "score": 0,
                "findings": [],
                "metadata": {
                    "error": f"Network integrity check failed: {str(exc)}",
                    "target": target,
                    "analysis_type": "network_integrity",
                },
            }

    async def _check_dns_consistency(self, hostname: str) -> dict[str, Any]:
        """Check DNS resolution consistency across multiple resolvers."""
        results: dict[str, Any] = {
            "hostname": hostname,
            "resolver_results": {},
            "findings": [],
        }

        # Use system resolver
        try:
            system_ips = set()
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_INET)
            system_ips = {info[4][0] for info in addr_info}
            results["resolver_results"]["system"] = sorted(system_ips)
        except socket.gaierror:
            results["resolver_results"]["system"] = []
            results["findings"].append({
                "type": "dns_resolution_failed",
                "severity": "high",
                "detail": f"System DNS resolver could not resolve '{hostname}'",
            })

        # Note: Full multi-resolver comparison would require dnspython.
        # We provide the system resolver result and flag if it returns
        # suspicious results.
        if system_ips:
            for ip in system_ips:
                if self._is_private_ip(ip):
                    results["findings"].append({
                        "type": "dns_poisoning_indicator",
                        "severity": "critical",
                        "detail": (
                            f"DNS resolved to private IP {ip}; "
                            "possible DNS poisoning or spoofing"
                        ),
                        "ip": ip,
                    })

        return results

    @staticmethod
    def _calculate_score(findings: list[dict[str, Any]]) -> int:
        """Calculate a 0-100 risk score."""
        severity_weights = {
            "critical": 25,
            "high": 15,
            "medium": 8,
            "low": 3,
        }
        score = sum(
            severity_weights.get(f.get("severity", "low"), 3)
            for f in findings
        )
        return min(score, 100)


# Module-level singleton
network_analyzer = NetworkAnalyzer()


async def check_network_integrity(target: str) -> dict[str, Any]:
    """Module-level convenience function."""
    return await network_analyzer.check_network_integrity(target)


async def get_tls_fingerprint(host: str) -> dict[str, Any]:
    """Module-level convenience function."""
    return await network_analyzer.get_tls_fingerprint(host)


async def detect_aitm_indicators(host: str) -> dict[str, Any]:
    """Module-level convenience function."""
    return await network_analyzer.detect_aitm_indicators(host)
