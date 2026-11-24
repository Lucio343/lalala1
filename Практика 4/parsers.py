"""
Парсеры Masscan и Nikto JSON — Python.
Приведение к единой схеме findings.
"""

import json
from typing import List, Dict
from datetime import datetime
import uuid


class MasscanParser:
    """Парсер вывода Masscan (JSON)."""
    
    SEVERITY_MAP = {
        22: "medium",    # SSH
        23: "high",      # Telnet
        3389: "high",    # RDP
        445: "critical", # SMB
        3306: "high",    # MySQL
        5432: "high",    # PostgreSQL
        8080: "medium",  # HTTP-alt
    }
    
    @staticmethod
    def parse(filepath: str) -> List[Dict]:
        findings = []
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                
                if 'ports' in data:
                    for port_info in data['ports']:
                        port = port_info.get('port')
                        findings.append({
                            'source': 'masscan',
                            'type': 'port',
                            'port': port,
                            'protocol': port_info.get('proto', 'tcp'),
                            'state': port_info.get('status', 'open'),
                            'severity': MasscanParser.SEVERITY_MAP.get(port, 'low'),
                            'description': f"Открытый порт {port}",
                            'cwe': None,
                            'cve': None,
                        })
        return findings


class NiktoParser:
    """Парсер вывода Nikto (JSON)."""
    
    @staticmethod
    def parse(filepath: str) -> List[Dict]:
        findings = []
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        # Nikto JSON имеет структуру с полем 'vulnerabilities'
        vulns = data.get('vulnerabilities', [])
        for v in vulns:
            osvdb = v.get('OSVDB', '')
            msg = v.get('msg', '')
            
            # Определение серьёзности по тексту
            severity = 'low'
            if 'X-Frame-Options' in msg or 'X-Content-Type' in msg:
                severity = 'medium'
            elif 'SQL' in msg or 'injection' in msg.lower():
                severity = 'critical'
            elif '.git' in msg or 'backup' in msg.lower():
                severity = 'high'
            
            findings.append({
                'source': 'nikto',
                'type': 'vulnerability',
                'port': data.get('port', 80),
                'protocol': 'http',
                'state': 'found',
                'severity': severity,
                'description': msg,
                'cwe': NiktoParser._map_cwe(msg),
                'cve': None,
            })
        return findings
    
    @staticmethod
    def _map_cwe(msg: str) -> str:
        """Сопоставление текста Nikto с CWE."""
        msg_lower = msg.lower()
        if 'sql' in msg_lower:
            return 'CWE-89'
        if 'xss' in msg_lower or 'script' in msg_lower:
            return 'CWE-79'
        if 'x-frame-options' in msg_lower:
            return 'CWE-1021'
        if '.git' in msg_lower:
            return 'CWE-538'
        return None


class NmapJSONParser:
    """Парсер JSON-вывода C++ парсера Nmap."""
    
    @staticmethod
    def parse(filepath: str) -> List[Dict]:
        findings = []
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        for host in data.get('hosts', []):
            for port in host.get('ports', []):
                if port.get('state') == 'open':
                    findings.append({
                        'source': 'nmap',
                        'type': 'service',
                        'port': port.get('port'),
                        'protocol': port.get('protocol', 'tcp'),
                        'state': port.get('state'),
                        'service': port.get('service'),
                        'version': port.get('version'),
                        'severity': NmapJSONParser._severity(port),
                        'description': f"{port.get('service')} {port.get('version')} на порту {port.get('port')}",
                        'cwe': None,
                        'cve': None,
                    })
        return findings
    
    @staticmethod
    def _severity(port: Dict) -> str:
        service = (port.get('service') or '').lower()
        version = (port.get('version') or '').lower()
        
        # Устаревшие версии — высокий риск
        if 'apache' in service and ('2.2' in version or '2.4.1' in version):
            return 'high'
        if 'openssh' in service and ('7.' in version or '6.' in version):
            return 'high'
        if 'nginx' in service and '1.1' in version:
            return 'medium'
        
        # Опасные сервисы
        if service in ('telnet', 'ftp', 'rlogin'):
            return 'critical'
        
        return 'low'
