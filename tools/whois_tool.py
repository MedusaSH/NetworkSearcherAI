#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module pour l'outil whois
"""

import re
from typing import Dict
from .base_tool import BaseTool


class WhoisTool(BaseTool):
    """Gestionnaire pour l'outil whois"""
    
    def __init__(self):
        super().__init__("whois")
    
    def generate_command(self, instruction: str, parameters: Dict) -> list:
        """Génère la commande whois"""
        cmd = ["whois"]
        
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
                raise ValueError("Aucun domaine ou IP trouvé dans la commande")
        
        return cmd
    
    def execute(self, instruction: str, parameters: Dict) -> Dict:
        """Exécute whois et analyse les résultats"""
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
            
            summary = self._parse_whois_output(output, parameters)
            analysis = self._analyze_whois_results(summary)
            
            return {
                'command': ' '.join(cmd),
                'summary': summary['summary'],
                'details': summary['details'],
                'raw_output': output[:2000] + "..." if len(output) > 2000 else output,  
                'analysis': analysis['analysis'],
                'risks': analysis['risks'],
                'recommendations': analysis['recommendations'],
                'requires_sudo': False
            }
        except Exception as e:
            return {
                'command': ' '.join(cmd) if 'cmd' in locals() else 'N/A',
                'error': str(e),
                'requires_sudo': False
            }
    
    def _parse_whois_output(self, output: str, parameters: Dict) -> Dict:
        """Parse la sortie de whois"""
        summary = {
            'summary': '',
            'details': {}
        }
        
        lines = output.split('\n')
        
        key_fields = {
            'Domain Name': 'Nom du domaine',
            'Registrar': 'Registrar',
            'Creation Date': 'Date de création',
            'Updated Date': 'Date de mise à jour',
            'Expiry Date': 'Date d\'expiration',
            'Name Server': 'Serveur de noms',
            'Registrant': 'Propriétaire',
            'Admin': 'Administrateur',
            'Tech': 'Contact technique',
            'Organization': 'Organisation',
            'Country': 'Pays',
            'AS': 'AS Number',
            'NetRange': 'Plage réseau',
            'OrgName': 'Organisation',
            'OrgId': 'ID Organisation'
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
                        else:
                            summary['details'][label] = [summary['details'][label], value]
        
        for key in summary['details']:
            if isinstance(summary['details'][key], list):
                summary['details'][key] = ', '.join(set(summary['details'][key]))  
        
        target = parameters.get('domain') or parameters.get('ip', 'cible')
        summary['summary'] = f"Informations whois pour {target}: {len(summary['details'])} champ(s) extrait(s)"
        
        return summary
    
    def _analyze_whois_results(self, summary: Dict) -> Dict:
        """Analyse les résultats whois"""
        analysis = {
            'analysis': '',
            'risks': [],
            'recommendations': []
        }
        
        details = summary['details']
        
        if 'Date d\'expiration' in details:
            analysis['analysis'] = f"Domaine enregistré, expiration: {details['Date d\'expiration']}. "
        elif 'Date de création' in details:
            analysis['analysis'] = f"Domaine créé le: {details['Date de création']}. "
        else:
            analysis['analysis'] = "Informations d'enregistrement trouvées. "
        
        if 'Propriétaire' in details or 'Registrant' in details:
            registrant = details.get('Propriétaire') or details.get('Registrant', '')
            if '@' in str(registrant) and 'privacy' not in str(registrant).lower():
                analysis['risks'].append("Informations du propriétaire visibles publiquement (pas de protection WHOIS)")
                analysis['recommendations'].append("Envisager d'activer la protection WHOIS/privacy pour le domaine")
        
        if 'Serveur de noms' in details:
            ns_count = len(str(details['Serveur de noms']).split(','))
            if ns_count < 2:
                analysis['risks'].append("Moins de 2 serveurs de noms configurés (recommandé: au moins 2)")
                analysis['recommendations'].append("Configurer au moins 2 serveurs de noms pour la redondance")
        
        if 'AS Number' in details:
            analysis['analysis'] += f"AS Number: {details['AS Number']}. "
        
        if 'Plage réseau' in details:
            analysis['analysis'] += f"Plage réseau: {details['Plage réseau']}. "
        
        if not analysis['risks']:
            analysis['analysis'] += "Aucun problème de sécurité majeur détecté dans les informations publiques."
        
        return analysis

