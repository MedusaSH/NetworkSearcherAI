#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Handler pour l'outil nmap
"""

import re
from typing import Dict, List
from .base_handler import BaseHandler


class NmapHandler(BaseHandler):
    """Handler pour l'outil nmap"""
    
    def __init__(self, simulation_mode: bool = False, auto_install: bool = True):
        super().__init__("nmap", simulation_mode=simulation_mode, auto_install=auto_install)
    
    def generate_command(self, instruction: str, parameters: Dict) -> List[str]:
        cmd = ["nmap"]
        instruction_lower = instruction.lower()
        
        scan_type = parameters.get('scan_type', '').lower()
        
        timing_level = parameters.get('timing', '4')
        if timing_level not in ['0', '1', '2', '3', '4', '5']:
            timing_level = '4'
        
        if scan_type == 'os' or 'juste l\'os' in instruction_lower or 'uniquement l\'os' in instruction_lower or 'seulement l\'os' in instruction_lower or ('os' in instruction_lower and ('juste' in instruction_lower or 'uniquement' in instruction_lower or 'seulement' in instruction_lower)):
            cmd.extend(["-O", "--osscan-guess", "--fuzzy", "-Pn", f"-T{timing_level}"])
        elif scan_type == 'version' or 'juste la version' in instruction_lower or 'uniquement la version' in instruction_lower or ('version' in instruction_lower and ('juste' in instruction_lower or 'uniquement' in instruction_lower)):
            cmd.extend(["-sV", "--version-intensity", "5", "-Pn", f"-T{timing_level}"])
        elif scan_type == 'ports' or 'juste les ports' in instruction_lower or 'uniquement les ports' in instruction_lower:
            cmd.extend(["-Pn", f"-T{timing_level}"])
        elif "tout" in instruction_lower or "complet" in instruction_lower or "utile" in instruction_lower:
            cmd.extend(["-A", "-sV", "-O", "--osscan-guess", "-Pn", f"-T{timing_level}"])
        elif "rapide" in instruction_lower or "quick" in instruction_lower:
            cmd.extend(["-F", f"-T5"])
        elif "stealth" in instruction_lower or "furtif" in instruction_lower:
            cmd.extend(["-sS", f"-T2"])
        else:
            cmd.extend(["-sV", "--version-intensity", "5", "-Pn", f"-T{timing_level}"])
        
        # Ports spécifiques
        if 'port' in parameters:
            cmd.extend(["-p", str(parameters['port'])])
        elif 'ports' in parameters:
            ports_str = ",".join(parameters['ports'])
            cmd.extend(["-p", ports_str])
        
        if 'ip' in parameters:
            cmd.append(parameters['ip'])
        elif 'domain' in parameters:
            cmd.append(parameters['domain'])
        else:
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
            
            ip_match = re.search(ip_pattern, instruction)
            domain_match = re.search(domain_pattern, instruction)
            
            if ip_match:
                cmd.append(ip_match.group())
            elif domain_match:
                cmd.append(domain_match.group())
            else:
                raise ValueError("Aucune cible (IP ou domaine) trouvée")
        
        return cmd
    
    def execute(self, instruction: str, parameters: Dict) -> Dict:
        """Exécute nmap et analyse les résultats"""
        try:
            cmd = self.generate_command(instruction, parameters)
            requires_sudo = "-O" in cmd
            
            result = self._run_command(cmd, requires_sudo=False)
            
            if not result['success'] and requires_sudo and result.get('error') and ('root' in result['error'].lower() or 'privileges' in result['error'].lower()):
                result = self._run_command(cmd, requires_sudo=True)
                requires_sudo = True
            
            if not result['success']:
                return {
                    'command': ' '.join(cmd),
                    'error': result.get('error') or result.get('output', 'Erreur inconnue'),
                    'raw_output': result.get('output', ''),
                    'requires_sudo': requires_sudo,
                    'simulated': result.get('simulated', False)
                }
            
            output = result['output']
            summary = self._parse_nmap_output(output)
            analysis = self.analyze_results(output, parameters)
            
            return {
                'command': ' '.join(cmd),
                'summary': summary['summary'],
                'details': summary['details'],
                'raw_output': output,
                'analysis': analysis['analysis'],
                'risks': analysis['risks'],
                'recommendations': analysis['recommendations'],
                'requires_sudo': requires_sudo,
                'simulated': result.get('simulated', False),
                'success': True
            }
        except Exception as e:
            return {
                'command': ' '.join(cmd) if 'cmd' in locals() else 'N/A',
                'error': str(e),
                'requires_sudo': False,
                'simulated': self.simulation_mode
            }
    
    def _parse_nmap_output(self, output: str) -> Dict:
        """Parse la sortie de nmap"""
        summary = {'summary': '', 'details': {}}
        lines = output.split('\n')
        
        host_line = [l for l in lines if 'Nmap scan report for' in l]
        if host_line:
            summary['details']['Cible'] = host_line[0].split('for')[-1].strip()
        
        open_ports = []
        services = []
        
        for line in lines:
            if '/tcp' in line or '/udp' in line:
                parts = line.split()
                if len(parts) >= 3 and parts[1] == 'open':
                    port_proto = parts[0]
                    service = parts[2] if len(parts) > 2 else 'unknown'
                    version = ' '.join(parts[3:]) if len(parts) > 3 else ''
                    open_ports.append(port_proto)
                    services.append(f"{port_proto} - {service} {version}".strip())
        
        summary['details']['Ports ouverts'] = ', '.join(open_ports) if open_ports else 'Aucun'
        summary['details']['Services'] = '\n    '.join(services) if services else 'Aucun service détecté'
        
        os_lines = [l for l in lines if 'OS details' in l or 'Running:' in l]
        if os_lines:
            summary['details']['OS'] = os_lines[0].split(':')[-1].strip()
        
        if open_ports:
            summary['summary'] = f"Scan terminé: {len(open_ports)} port(s) ouvert(s) détecté(s)"
        else:
            summary['summary'] = "Scan terminé: Aucun port ouvert détecté"
        
        return summary
    
    def analyze_results(self, output: str, parameters: Dict) -> Dict:
        """Analyse les résultats et génère des insights"""
        analysis = {'analysis': '', 'risks': [], 'recommendations': []}
        
        summary = self._parse_nmap_output(output)
        services = summary['details'].get('Services', '')
        ports = summary['details'].get('Ports ouverts', '')
        
        risky_ports = {
            '21': 'FTP - peut être non sécurisé',
            '23': 'Telnet - non chiffré',
            '80': 'HTTP - non chiffré',
            '135': 'RPC - peut exposer des services',
            '139': 'NetBIOS - peut exposer des informations',
            '445': 'SMB - peut être vulnérable',
            '1433': 'SQL Server - peut être exposé',
            '3306': 'MySQL - peut être exposé',
            '3389': 'RDP - peut être exposé',
            '5432': 'PostgreSQL - peut être exposé'
        }
        
        for port, risk_desc in risky_ports.items():
            if port in ports:
                analysis['risks'].append(f"Port {port} ouvert: {risk_desc}")
        
        if ports and ports != 'Aucun':
            port_count = len(ports.split(','))
            analysis['analysis'] = f"L'hôte expose {port_count} port(s) ouvert(s). "
            
            if port_count > 10:
                analysis['analysis'] += "Nombre élevé de ports ouverts, surface d'attaque importante."
            elif port_count > 5:
                analysis['analysis'] += "Plusieurs services exposés, vérification de sécurité recommandée."
            else:
                analysis['analysis'] += "Configuration relativement restrictive."
        else:
            analysis['analysis'] = "Aucun port ouvert détecté. L'hôte peut être protégé par un firewall ou être down."
        
        if analysis['risks']:
            analysis['recommendations'].append("Vérifier la nécessité de chaque service exposé")
            analysis['recommendations'].append("Mettre à jour tous les services vers les dernières versions")
            analysis['recommendations'].append("Configurer un firewall pour limiter l'accès aux services")
        
        if 'SSH' in services or '22' in ports:
            analysis['recommendations'].append("Pour SSH: désactiver l'authentification par mot de passe, utiliser des clés")
        
        if 'HTTP' in services or '80' in ports:
            analysis['recommendations'].append("Pour HTTP: rediriger vers HTTPS (port 443)")
        
        return analysis

