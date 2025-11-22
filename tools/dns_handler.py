#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Handler pour les outils DNS (dig et whois)
"""

import re
from typing import Dict, List
from .base_handler import BaseHandler


class DnsHandler(BaseHandler):
    """Handler pour les outils DNS (dig et whois)"""
    
    def __init__(self, simulation_mode: bool = False, tool: str = "dig", auto_install: bool = True):
        super().__init__(tool, simulation_mode=simulation_mode, auto_install=auto_install)
        self.tool_type = tool
    
    def generate_command(self, instruction: str, parameters: Dict) -> List[str]:
        """Génère la commande dig ou whois"""
        cmd = [self.tool_type]
        instruction_lower = instruction.lower()
        
        if self.tool_type == "dig":
            if "mx" in instruction_lower:
                cmd.append("MX")
            elif "ns" in instruction_lower or "nameserver" in instruction_lower:
                cmd.append("NS")
            elif "txt" in instruction_lower:
                cmd.append("TXT")
            elif "aaaa" in instruction_lower or "ipv6" in instruction_lower:
                cmd.append("AAAA")
            elif "cname" in instruction_lower:
                cmd.append("CNAME")
            else:
                cmd.append("A")
            
            if 'domain' in parameters:
                cmd.append(parameters['domain'])
            else:
                domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
                domain_match = re.search(domain_pattern, instruction)
                if domain_match:
                    cmd.append(domain_match.group())
                else:
                    raise ValueError("Aucun domaine trouvé")
            
            if "court" in instruction_lower or "short" in instruction_lower:
                cmd.append("+short")
            else:
                cmd.append("+noall")
                cmd.append("+answer")
        
        elif self.tool_type == "whois":
            if 'domain' in parameters:
                cmd.append(parameters['domain'])
            elif 'ip' in parameters:
                cmd.append(parameters['ip'])
            else:
                domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
                ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                
                domain_match = re.search(domain_pattern, instruction)
                ip_match = re.search(ip_pattern, instruction)
                
                if domain_match:
                    cmd.append(domain_match.group())
                elif ip_match:
                    cmd.append(ip_match.group())
                else:
                    raise ValueError("Aucun domaine ou IP trouvé")
        
        return cmd
    
    def execute(self, instruction: str, parameters: Dict) -> Dict:
        """Exécute dig ou whois"""
        try:
            cmd = self.generate_command(instruction, parameters)
            result = self._run_command(cmd, requires_sudo=False)
            
            if not result['success']:
                return {
                    'command': ' '.join(cmd),
                    'error': result.get('error'),
                    'requires_sudo': False,
                    'simulated': result.get('simulated', False)
                }
            
            output = result['output']
            
            if self.tool_type == "dig":
                summary = self._parse_dig_output(output, parameters.get('domain', ''))
            else:
                summary = self._parse_whois_output(output, parameters)
            
            analysis = self.analyze_results(output, parameters)
            
            return {
                'command': ' '.join(cmd),
                'summary': summary['summary'],
                'details': summary['details'],
                'raw_output': output[:2000] + "..." if len(output) > 2000 else output,
                'analysis': analysis['analysis'],
                'risks': analysis.get('risks', []),
                'recommendations': analysis.get('recommendations', []),
                'requires_sudo': False,
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
    
    def _parse_dig_output(self, output: str, domain: str) -> Dict:
        """Parse la sortie de dig"""
        summary = {'summary': '', 'details': {}}
        lines = output.split('\n')
        
        answers = []
        for line in lines:
            if 'IN' in line and ('A' in line or 'AAAA' in line or 'MX' in line or 'NS' in line or 'TXT' in line):
                parts = line.split()
                if len(parts) >= 5:
                    record_type = parts[3]
                    record_value = ' '.join(parts[4:])
                    answers.append(f"{record_type}: {record_value}")
        
        summary['details']['Enregistrements DNS'] = '\n    '.join(answers) if answers else 'Aucun'
        
        dns_server = None
        for line in lines:
            if 'SERVER:' in line:
                parts = line.split('SERVER:')
                if len(parts) > 1:
                    dns_server = parts[1].strip().split()[0]
                    break
        
        if dns_server:
            summary['details']['Serveur DNS'] = dns_server
        
        query_time = None
        for line in lines:
            if 'Query time:' in line:
                parts = line.split('Query time:')
                if len(parts) > 1:
                    query_time = parts[1].strip().split()[0]
                    break
        
        if query_time:
            summary['details']['Temps de réponse'] = f"{query_time} ms"
        
        summary['summary'] = f"Requête DNS pour {domain}: {len(answers)} enregistrement(s) trouvé(s)"
        
        return summary
    
    def _parse_whois_output(self, output: str, parameters: Dict) -> Dict:
        """Parse la sortie de whois"""
        summary = {'summary': '', 'details': {}}
        lines = output.split('\n')
        
        key_fields = {
            'Domain Name': 'Nom du domaine',
            'Registrar': 'Registrar',
            'Creation Date': 'Date de création',
            'Updated Date': 'Date de mise à jour',
            'Expiry Date': 'Date d\'expiration',
            'Name Server': 'Serveur de noms',
            'Registrant': 'Propriétaire',
            'Organization': 'Organisation',
            'Country': 'Pays',
            'AS': 'AS Number',
            'NetRange': 'Plage réseau',
            'OrgName': 'Organisation'
        }
        
        for line in lines:
            line_lower = line.lower()
            for key, label in key_fields.items():
                if key.lower() in line_lower and ':' in line:
                    value = line.split(':', 1)[1].strip()
                    if value and value not in ['N/A', 'None', '']:
                        if label not in summary['details']:
                            summary['details'][label] = []
                        if isinstance(summary['details'][label], list):
                            summary['details'][label].append(value)
        
        for key in summary['details']:
            if isinstance(summary['details'][key], list):
                summary['details'][key] = ', '.join(set(summary['details'][key]))
        
        target = parameters.get('domain') or parameters.get('ip', 'cible')
        summary['summary'] = f"Informations whois pour {target}: {len(summary['details'])} champ(s) extrait(s)"
        
        return summary
    
    def analyze_results(self, output: str, parameters: Dict) -> Dict:
        """Analyse les résultats DNS"""
        analysis = {'analysis': '', 'risks': [], 'recommendations': []}
        
        if self.tool_type == "dig":
            analysis['analysis'] = "La résolution DNS fonctionne correctement."
        else:
            if 'Date d\'expiration' in output:
                analysis['analysis'] = "Domaine enregistré, informations disponibles."
            else:
                analysis['analysis'] = "Informations d'enregistrement trouvées."
            
            if 'Propriétaire' in output and '@' in output and 'privacy' not in output.lower():
                analysis['risks'].append("Informations du propriétaire visibles publiquement")
                analysis['recommendations'].append("Envisager d'activer la protection WHOIS/privacy")
        
        return analysis

