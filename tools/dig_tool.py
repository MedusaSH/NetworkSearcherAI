#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module pour l'outil dig
"""

import re
from typing import Dict
from .base_tool import BaseTool


class DigTool(BaseTool):
    """Gestionnaire pour l'outil dig"""
    
    def __init__(self):
        super().__init__("dig")
    
    def generate_command(self, instruction: str, parameters: Dict) -> list:
        """Génère la commande dig"""
        cmd = ["dig"]
        
        if "mx" in instruction.lower():
            cmd.append("MX")
        elif "ns" in instruction.lower() or "nameserver" in instruction.lower():
            cmd.append("NS")
        elif "txt" in instruction.lower():
            cmd.append("TXT")
        elif "aaaa" in instruction.lower() or "ipv6" in instruction.lower():
            cmd.append("AAAA")
        elif "cname" in instruction.lower():
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
                raise ValueError("Aucun domaine trouvé dans la commande")
        
        if "court" in instruction.lower() or "short" in instruction.lower():
            cmd.append("+short")
        else:
            cmd.append("+noall")
            cmd.append("+answer")
        
        return cmd
    
    def execute(self, instruction: str, parameters: Dict) -> Dict:
        """Exécute dig et analyse les résultats"""
        try:
            cmd = self.generate_command(instruction, parameters)
            result = self._run_command(cmd, requires_sudo=False)
            
            if not result['success']:
                return {
                    'command': ' '.join(cmd),
                    'error': result['error'],
                    'requires_sudo': False
                }
            
            output = result['output']
            
            summary = self._parse_dig_output(output, parameters.get('domain', ''))
            analysis = self._analyze_dns_results(summary)
            
            return {
                'command': ' '.join(cmd),
                'summary': summary['summary'],
                'details': summary['details'],
                'raw_output': output,
                'analysis': analysis['analysis'],
                'recommendations': analysis['recommendations'],
                'requires_sudo': False
            }
        except Exception as e:
            return {
                'command': ' '.join(cmd) if 'cmd' in locals() else 'N/A',
                'error': str(e),
                'requires_sudo': False
            }
    
    def _parse_dig_output(self, output: str, domain: str) -> Dict:
        """Parse la sortie de dig"""
        summary = {
            'summary': '',
            'details': {}
        }
        
        lines = output.split('\n')
        
        answers = []
        for line in lines:
            if 'IN' in line and ('A' in line or 'AAAA' in line or 'MX' in line or 'NS' in line or 'TXT' in line or 'CNAME' in line):
                parts = line.split()
                if len(parts) >= 5:
                    record_type = parts[3]
                    record_value = ' '.join(parts[4:])
                    answers.append(f"{record_type}: {record_value}")
        
        summary['details']['Enregistrements DNS'] = '\n    '.join(answers) if answers else 'Aucun enregistrement trouvé'
        
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
    
    def _analyze_dns_results(self, summary: Dict) -> Dict:
        """Analyse les résultats DNS"""
        analysis = {
            'analysis': '',
            'recommendations': []
        }
        
        records = summary['details'].get('Enregistrements DNS', '')
        
        if records and records != 'Aucun enregistrement trouvé':
            analysis['analysis'] = "La résolution DNS fonctionne correctement. "
            
            if 'MX' in records:
                analysis['analysis'] += "Enregistrements MX présents (email configuré). "
            
            if 'NS' in records:
                analysis['analysis'] += "Serveurs de noms configurés. "
        else:
            analysis['analysis'] = "Aucun enregistrement DNS trouvé. Le domaine peut être invalide ou mal configuré."
            analysis['recommendations'].append("Vérifier que le domaine est correctement enregistré")
            analysis['recommendations'].append("Vérifier la configuration DNS du domaine")
        
        return analysis

