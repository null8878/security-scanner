#!/usr/bin/env python3
"""
Security Scanner - Vulnerability assessment tool
"""

import socket
import ssl
import json
import subprocess
import sys
import concurrent.futures
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Optional
import argparse
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class ScanResult:
    target: str
    scan_type: str
    timestamp: str
    findings: List[dict]
    risk_level: str
    summary: str

@dataclass
class PortResult:
    port: int
    state: str
    service: str
    version: Optional[str] = None

@dataclass
class SSLResult:
    issuer: str
    subject: str
    not_before: str
    not_after: str
    protocol: str
    cipher: str
    is_valid: bool
    days_until_expiry: int

class SecurityScanner:
    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]

    DANGEROUS_PORTS = {
        21: 'FTP - Consider disabling or using SFTP',
        23: 'Telnet - Unencrypted, disable immediately',
        445: 'SMB - Ensure proper firewall rules',
        3389: 'RDP - Ensure network-level authentication',
        5900: 'VNC - Ensure encryption is enabled',
        6379: 'Redis - Ensure authentication is configured',
        27017: 'MongoDB - Ensure authentication is configured',
    }

    WEAK_CIPHERS = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon']

    def __init__(self, target: str):
        self.target = target
        self.results = []

    def scan_ports(self, ports: List[int] = None, threads: int = 100) -> ScanResult:
        """Scan ports for open services"""
        if ports is None:
            ports = self.COMMON_PORTS

        logger.info(f"Scanning {len(ports)} ports on {self.target}")
        open_ports = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self._check_port, port): port for port in ports}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result and result.state == 'open':
                    open_ports.append(result)
                    logger.info(f"Port {result.port}/tcp open - {result.service}")

        findings = []
        risk_level = 'low'

        for port_result in open_ports:
            finding = {
                'type': 'open_port',
                'port': port_result.port,
                'service': port_result.service,
                'version': port_result.version,
            }

            if port_result.port in self.DANGEROUS_PORTS:
                finding['recommendation'] = self.DANGEROUS_PORTS[port_result.port]
                finding['severity'] = 'high'
                risk_level = 'high'
            else:
                finding['severity'] = 'info'

            findings.append(finding)

        return ScanResult(
            target=self.target,
            scan_type='port_scan',
            timestamp=datetime.utcnow().isoformat(),
            findings=findings,
            risk_level=risk_level,
            summary=f"Found {len(open_ports)} open ports"
        )

    def _check_port(self, port: int) -> Optional[PortResult]:
        """Check if a specific port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((self.target, port))

            if result == 0:
                service = self._detect_service(port)
                return PortResult(port=port, state='open', service=service)
            sock.close()
        except:
            pass
        return None

    def _detect_service(self, port: int) -> str:
        """Detect service running on port"""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
            1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC',
            6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
            27017: 'MongoDB'
        }
        return services.get(port, 'unknown')

    def check_ssl(self, port: int = 443) -> ScanResult:
        """Analyze SSL/TLS configuration"""
        findings = []
        risk_level = 'low'

        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    protocol = ssock.version()

                    # Check certificate validity
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.utcnow()).days

                    ssl_result = SSLResult(
                        issuer=dict(x[0] for x in cert['issuer']).get('organizationName', 'Unknown'),
                        subject=dict(x[0] for x in cert['subject']).get('commonName', 'Unknown'),
                        not_before=cert['notBefore'],
                        not_after=cert['notAfter'],
                        protocol=protocol,
                        cipher=cipher[0] if cipher else 'Unknown',
                        is_valid=True,
                        days_until_expiry=days_until_expiry
                    )

                    if days_until_expiry < 30:
                        findings.append({
                            'type': 'ssl_expiry',
                            'severity': 'high' if days_until_expiry < 7 else 'medium',
                            'message': f'Certificate expires in {days_until_expiry} days',
                            'recommendation': 'Renew SSL certificate immediately'
                        })
                        risk_level = 'high'

                    if any(weak in cipher[0] for weak in self.WEAK_CIPHERS):
                        findings.append({
                            'type': 'weak_cipher',
                            'severity': 'high',
                            'message': f'Weak cipher detected: {cipher[0]}',
                            'recommendation': 'Update to use strong ciphers only'
                        })
                        risk_level = 'high'

                    if protocol in ('TLSv1', 'TLSv1.1', 'SSLv3'):
                        findings.append({
                            'type': 'weak_protocol',
                            'severity': 'high',
                            'message': f'Weak protocol: {protocol}',
                            'recommendation': 'Disable TLS 1.0/1.1, use TLS 1.2+'
                        })
                        risk_level = 'high'

        except ssl.SSLCertVerificationError as e:
            findings.append({
                'type': 'ssl_error',
                'severity': 'critical',
                'message': f'SSL verification failed: {str(e)}',
                'recommendation': 'Fix certificate chain'
            })
            risk_level = 'critical'
        except Exception as e:
            findings.append({
                'type': 'ssl_connection_error',
                'severity': 'medium',
                'message': f'Could not establish SSL connection: {str(e)}'
            })

        return ScanResult(
            target=self.target,
            scan_type='ssl_check',
            timestamp=datetime.utcnow().isoformat(),
            findings=findings,
            risk_level=risk_level,
            summary=f"SSL check complete - {len(findings)} issues found"
        )

    def check_headers(self) -> ScanResult:
        """Check security headers"""
        findings = []
        risk_level = 'low'

        try:
            import urllib.request
            req = urllib.request.Request(f'https://{self.target}', method='HEAD')
            req.add_header('User-Agent', 'SecurityScanner/1.0')
            response = urllib.request.urlopen(req, timeout=10)
            headers = dict(response.headers)

            security_headers = {
                'Strict-Transport-Security': {'severity': 'high', 'recommendation': 'Add HSTS header'},
                'X-Content-Type-Options': {'severity': 'medium', 'recommendation': 'Add nosniff header'},
                'X-Frame-Options': {'severity': 'medium', 'recommendation': 'Add frame protection'},
                'X-XSS-Protection': {'severity': 'low', 'recommendation': 'Add XSS protection'},
                'Content-Security-Policy': {'severity': 'high', 'recommendation': 'Implement CSP'},
                'Referrer-Policy': {'severity': 'low', 'recommendation': 'Add referrer policy'},
                'Permissions-Policy': {'severity': 'medium', 'recommendation': 'Add permissions policy'},
            }

            for header, config in security_headers.items():
                if header.lower() not in [h.lower() for h in headers]:
                    findings.append({
                        'type': 'missing_header',
                        'severity': config['severity'],
                        'message': f'Missing security header: {header}',
                        'recommendation': config['recommendation']
                    })
                    if config['severity'] in ('high', 'critical'):
                        risk_level = 'high'

        except Exception as e:
            findings.append({
                'type': 'header_check_error',
                'severity': 'medium',
                'message': f'Could not check headers: {str(e)}'
            })

        return ScanResult(
            target=self.target,
            scan_type='header_check',
            timestamp=datetime.utcnow().isoformat(),
            findings=findings,
            risk_level=risk_level,
            summary=f"Header check complete - {len(findings)} issues found"
        )

    def full_scan(self) -> List[ScanResult]:
        """Run all security checks"""
        logger.info(f"Starting full security scan on {self.target}")

        results = [
            self.scan_ports(),
            self.check_ssl(),
            self.check_headers(),
        ]

        self.results = results
        return results

    def generate_report(self, format: str = 'json') -> str:
        """Generate scan report"""
        report = {
            'target': self.target,
            'scan_time': datetime.utcnow().isoformat(),
            'results': [asdict(r) for r in self.results],
            'summary': {
                'total_findings': sum(len(r.findings) for r in self.results),
                'critical': sum(1 for r in self.results for f in r.findings if f.get('severity') == 'critical'),
                'high': sum(1 for r in self.results for f in r.findings if f.get('severity') == 'high'),
                'medium': sum(1 for r in self.results for f in r.findings if f.get('severity') == 'medium'),
                'low': sum(1 for r in self.results for f in r.findings if f.get('severity') == 'low'),
            }
        }

        if format == 'json':
            return json.dumps(report, indent=2)
        elif format == 'html':
            return self._generate_html_report(report)
        return json.dumps(report, indent=2)

    def _generate_html_report(self, report: dict) -> str:
        """Generate HTML report"""
        findings_html = ''
        for result in report['results']:
            for finding in result['findings']:
                severity_color = {'critical': '#dc3545', 'high': '#fd7e14', 'medium': '#ffc107', 'low': '#28a745'}.get(finding.get('severity', 'low'), '#6c757d')
                findings_html += f'''
                <tr>
                    <td><span style="color:{severity_color};font-weight:bold">{finding.get('severity', 'info').upper()}</span></td>
                    <td>{finding.get('type', 'unknown')}</td>
                    <td>{finding.get('message', '')}</td>
                    <td>{finding.get('recommendation', 'N/A')}</td>
                </tr>
                '''

        return f'''
        <!DOCTYPE html>
        <html>
        <head><title>Security Scan Report - {report['target']}</title></head>
        <body>
            <h1>Security Scan Report</h1>
            <p>Target: {report['target']}</p>
            <p>Scan Time: {report['scan_time']}</p>
            <h2>Summary</h2>
            <p>Total Findings: {report['summary']['total_findings']}</p>
            <p>Critical: {report['summary']['critical']} | High: {report['summary']['high']} | Medium: {report['summary']['medium']} | Low: {report['summary']['low']}</p>
            <h2>Findings</h2>
            <table border="1" cellpadding="8">
                <tr><th>Severity</th><th>Type</th><th>Details</th><th>Recommendation</th></tr>
                {findings_html}
            </table>
        </body>
        </html>
        '''

def main():
    parser = argparse.ArgumentParser(description='Security Scanner')
    parser.add_argument('--target', required=True, help='Target host or IP')
    parser.add_argument('--scan', choices=['port', 'ssl', 'headers', 'full'], default='full')
    parser.add_argument('--output', choices=['json', 'html'], default='json')
    parser.add_argument('--output-file', help='Output file path')
    args = parser.parse_args()

    scanner = SecurityScanner(args.target)

    if args.scan == 'port':
        results = [scanner.scan_ports()]
    elif args.scan == 'ssl':
        results = [scanner.check_ssl()]
    elif args.scan == 'headers':
        results = [scanner.check_headers()]
    else:
        results = scanner.full_scan()

    report = scanner.generate_report(args.output)

    if args.output_file:
        with open(args.output_file, 'w') as f:
            f.write(report)
        logger.info(f"Report saved to {args.output_file}")
    else:
        print(report)

if __name__ == '__main__':
    main()
