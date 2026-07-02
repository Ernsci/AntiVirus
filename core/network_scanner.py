import subprocess
import re
import os


SUSPICIOUS_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 110: 'POP3', 143: 'IMAP',
    445: 'SMB', 1433: 'MSSQL', 3306: 'MySQL',
    3389: 'RDP', 4444: 'Metasploit', 5555: 'AndroidADB',
    6666: 'IRC/RAT', 6667: 'IRC', 6668: 'IRC',
    6669: 'IRC', 7777: 'RAT', 8443: 'HTTPS-Alt',
    9001: 'Tor', 9030: 'Tor', 9050: 'TorSOCKS',
    31337: 'BackOrifice', 12345: 'NetBus',
    27374: 'SubSeven', 27665: 'Trinoo',
    20034: 'NetBus2', 10000: 'Backdoor',
    65535: 'Unknown'
}

RAT_PORTS = {1604, 2404, 2505, 2606, 2707, 4782, 4783,
             5500, 5501, 5502, 5503, 5552, 5553, 5555,
             6606, 7707, 8808, 8818, 8888, 9999}


class NetworkScanner:
    def __init__(self):
        self._netstat_cache = None

    def get_connections(self):
        if self._netstat_cache:
            return self._netstat_cache
        try:
            result = subprocess.run(
                ['netstat', '-ano'],
                capture_output=True, text=True, timeout=10
            )
            connections = []
            for line in result.stdout.split('\n'):
                parts = line.strip().split()
                if len(parts) >= 5 and parts[0] in ('TCP', 'UDP'):
                    try:
                        proto = parts[0]
                        local = parts[1]
                        remote = parts[2] if proto == 'TCP' else parts[1]
                        state = parts[3] if proto == 'TCP' and len(parts) > 4 else ''
                        pid = parts[-1]
                        connections.append({
                            'protocol': proto,
                            'local': local,
                            'remote': remote,
                            'state': state,
                            'pid': pid
                        })
                    except (IndexError, ValueError):
                        pass
            self._netstat_cache = connections
            return connections
        except Exception:
            return []

    def scan_connections(self):
        findings = []
        conns = self.get_connections()

        for conn in conns:
            remote = conn['remote']
            pid = conn['pid']
            proto = conn['protocol']

            if ':' in remote:
                host, port_str = remote.rsplit(':', 1)
                try:
                    port = int(port_str)
                except ValueError:
                    continue
                if proto == 'TCP' and conn['state'] == 'ESTABLISHED':
                    if port in RAT_PORTS:
                        findings.append({
                            'type': 'rat_connection',
                            'detail': f'RAT port {port} ({SUSPICIOUS_PORTS.get(port, "Unknown")}) '
                                      f'to {host} PID:{pid}',
                            'severity': 'critical'
                        })
                    elif port in (21, 22, 23, 3389) and host.startswith(('192.', '10.', '172.')):
                        pass
                    elif port in SUSPICIOUS_PORTS and not host.startswith(('127.', '192.168.', '10.')):
                        findings.append({
                            'type': 'suspicious_connection',
                            'detail': f'Port {port} ({SUSPICIOUS_PORTS.get(port, "Unknown")}) '
                                      f'to {host} PID:{pid}',
                            'severity': 'high'
                        })

                if proto == 'TCP' and conn['state'] == 'LISTENING':
                    if port in RAT_PORTS:
                        findings.append({
                            'type': 'rat_listener',
                            'detail': f'Listening on RAT port {port} PID:{pid}',
                            'severity': 'critical'
                        })
                    if port > 49152 and pid and pid != '0' and pid != '4':
                        findings.append({
                            'type': 'high_port_listener',
                            'detail': f'Listening on high port {port} PID:{pid}',
                            'severity': 'low'
                        })

        return findings

    def find_process_by_port(self, port):
        conns = self.get_connections()
        for conn in conns:
            if ':' in conn['local']:
                _, p = conn['local'].rsplit(':', 1)
                if p == str(port):
                    return conn['pid']
        return None

    def clear_cache(self):
        self._netstat_cache = None
