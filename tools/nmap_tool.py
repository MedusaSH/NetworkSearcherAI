#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module pour l'outil nmap
"""

import re
from typing import Dict, List
from .base_tool import BaseTool


class NmapTool(BaseTool):
    """Gestionnaire pour l'outil nmap"""
    
    def __init__(self):
        super().__init__("nmap")
    
    def generate_command(self, instruction: str, parameters: Dict) -> list:
        """Génère la commande nmap"""
        cmd = ["nmap"]
        instruction_lower = instruction.lower()
        
        if "tout" in instruction_lower or "complet" in instruction_lower or "utile" in instruction_lower:
            cmd.extend(["-A", "-sV", "-O", "-Pn"])
        elif "rapide" in instruction_lower or "quick" in instruction_lower:
            cmd.append("-F")  
        elif "stealth" in instruction_lower or "furtif" in instruction_lower:
            cmd.append("-sS")  
        else:
            cmd.extend(["-sV", "-Pn"])
        
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
                raise ValueError("Aucune cible (IP ou domaine) trouvée dans la commande")
        
        return cmd
    
    def execute(self, instruction: str, parameters: Dict) -> Dict:
        """Exécute nmap et analyse les résultats"""
        try:
            cmd = self.generate_command(instruction, parameters)
            
            requires_sudo = "-O" in cmd
            
            result = self._run_command(cmd, requires_sudo=False)
            
            if not result['success'] and requires_sudo and ('root' in result.get('error', '').lower() or 'privileges' in result.get('error', '').lower()):
                result = self._run_command(cmd, requires_sudo=True)
                requires_sudo = True
            
            if not result['success']:
                error_msg = result.get('error') or result.get('output', 'Erreur inconnue')
                return {
                    'command': ' '.join(cmd),
                    'error': error_msg,
                    'raw_output': result.get('output', ''),  
                    'requires_sudo': requires_sudo
                }
            
            output = result['output']
            
            summary = self._parse_nmap_output(output)
            analysis = self._analyze_results(summary)
            
            return {
                'command': ' '.join(cmd),
                'summary': summary['summary'],
                'details': summary['details'],
                'raw_output': output,
                'analysis': analysis['analysis'],
                'risks': analysis['risks'],
                'recommendations': analysis['recommendations'],
                'requires_sudo': requires_sudo
            }
        except Exception as e:
            return {
                'command': ' '.join(cmd) if 'cmd' in locals() else 'N/A',
                'error': str(e),
                'requires_sudo': False
            }
    
    def _parse_nmap_output(self, output: str) -> Dict:
        """Parse la sortie de nmap"""
        summary = {
            'summary': '',
            'details': {}
        }
        
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
            summary['summary'] = "Scan terminé: Aucun port ouvert détecté (hôte peut être down ou filtré)"
        
        return summary
    
    def _analyze_results(self, summary: Dict) -> Dict:
        """Analyse les résultats et génère des recommandations"""
        analysis = {
            'analysis': '',
            'risks': [],
            'recommendations': []
        }
        
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

