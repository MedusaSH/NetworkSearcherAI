#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Handler pour l'outil iptables
"""

import re
from typing import Dict, List
from .base_handler import BaseHandler


class IptablesHandler(BaseHandler):
    """Handler pour l'outil iptables"""
    
    def __init__(self, simulation_mode: bool = False, auto_install: bool = True):
        super().__init__("iptables", simulation_mode=simulation_mode, auto_install=auto_install)
    
    def generate_command(self, instruction: str, parameters: Dict) -> List[str]:
        """Génère la commande iptables"""
        instruction_lower = instruction.lower()
        cmd = ["iptables"]
        
        if "bloque" in instruction_lower or "block" in instruction_lower:
            action = "-A"
            target = "DROP"
        elif "autorise" in instruction_lower or "allow" in instruction_lower:
            action = "-A"
            target = "ACCEPT"
        elif "supprime" in instruction_lower or "delete" in instruction_lower:
            action = "-D"
            target = None
        else:
            action = "-A"
            target = "DROP"
        
        if "entrant" in instruction_lower or "input" in instruction_lower:
            chain = "INPUT"
        elif "sortant" in instruction_lower or "output" in instruction_lower:
            chain = "OUTPUT"
        elif "forward" in instruction_lower:
            chain = "FORWARD"
        else:
            chain = "INPUT"
        
        cmd.append(action)
        cmd.append(chain)
        
        if 'protocol' in parameters:
            cmd.extend(["-p", parameters['protocol'].upper()])
        elif "tcp" in instruction_lower:
            cmd.extend(["-p", "tcp"])
        elif "udp" in instruction_lower:
            cmd.extend(["-p", "udp"])
        
        if 'port' in parameters:
            if "source" in instruction_lower:
                cmd.extend(["--sport", str(parameters['port'])])
            else:
                cmd.extend(["--dport", str(parameters['port'])])
        
        if 'ip' in parameters:
            if "source" in instruction_lower:
                cmd.extend(["-s", parameters['ip']])
            else:
                cmd.extend(["-d", parameters['ip']])
        
        if "sauf" in instruction_lower or "except" in instruction_lower:
            if "ssh" in instruction_lower:
                pass 
        
        if target:
            cmd.append("-j")
            cmd.append(target)
        
        return cmd
    
    def execute(self, instruction: str, parameters: Dict) -> Dict:
        """Exécute iptables"""
        try:
            cmd = self.generate_command(instruction, parameters)
            
            if "liste" in instruction.lower() or "list" in instruction.lower():
                list_cmd = ["iptables", "-L", "-v", "-n"]
                result = self._run_command(list_cmd, requires_sudo=True)
                
                if not result['success']:
                    return {
                        'command': ' '.join(list_cmd),
                        'error': result.get('error', "Impossible d'exécuter iptables"),
                        'requires_sudo': True,
                        'simulated': result.get('simulated', False)
                    }
                
                output = result['output']
                summary = self._parse_iptables_list(output)
                
                return {
                    'command': ' '.join(list_cmd),
                    'summary': summary['summary'],
                    'details': summary['details'],
                    'raw_output': output,
                    'analysis': summary['analysis'],
                    'requires_sudo': True,
                    'simulated': result.get('simulated', False)
                }
            else:
                explanation = self._explain_rule(cmd, instruction)
                
                return {
                    'command': ' '.join(cmd),
                    'summary': f"Règle iptables générée pour: {instruction}",
                    'details': explanation['details'],
                    'raw_output': '',
                    'analysis': explanation['analysis'],
                    'risks': explanation['risks'],
                    'recommendations': explanation['recommendations'],
                    'requires_sudo': True,
                    'simulated': self.simulation_mode,
                    'warning': 'Cette commande necessite sudo et modifie le firewall'
                }
        except Exception as e:
            return {
                'command': ' '.join(cmd) if 'cmd' in locals() else 'N/A',
                'error': str(e),
                'requires_sudo': True,
                'simulated': self.simulation_mode
            }
    
    def _parse_iptables_list(self, output: str) -> Dict:
        """Parse la sortie de iptables -L"""
        summary = {'summary': '', 'details': {}, 'analysis': ''}
        lines = output.split('\n')
        chains = {}
        current_chain = None
        
        for line in lines:
            if line.startswith('Chain'):
                current_chain = line.split()[1]
                chains[current_chain] = []
            elif current_chain and line.strip() and not line.startswith('target'):
                chains[current_chain].append(line.strip())
        
        rule_count = sum(len(rules) for rules in chains.values())
        summary['summary'] = f"Configuration iptables: {len(chains)} chaîne(s), {rule_count} règle(s)"
        summary['details'] = {
            'Chaînes': ', '.join(chains.keys()),
            'Règles par chaîne': {chain: len(rules) for chain, rules in chains.items()}
        }
        summary['analysis'] = f"Analyse: {len(chains.get('INPUT', []))} règle(s) INPUT, {len(chains.get('OUTPUT', []))} règle(s) OUTPUT"
        
        return summary
    
    def _explain_rule(self, cmd: List[str], instruction: str) -> Dict:
        """Explique ce que fait une règle iptables"""
        explanation = {
            'details': {},
            'analysis': '',
            'risks': [],
            'recommendations': []
        }
        
        if "-A INPUT" in ' '.join(cmd):
            explanation['details']['Action'] = "Ajout d'une règle à la chaîne INPUT"
        elif "-A OUTPUT" in ' '.join(cmd):
            explanation['details']['Action'] = "Ajout d'une règle à la chaîne OUTPUT"
        
        if "-j DROP" in ' '.join(cmd):
            explanation['details']['Effet'] = "Bloque les paquets correspondants"
        elif "-j ACCEPT" in ' '.join(cmd):
            explanation['details']['Effet'] = "Autorise les paquets correspondants"
        
        if "--dport" in cmd:
            idx = cmd.index("--dport")
            if idx + 1 < len(cmd):
                explanation['details']['Port destination'] = cmd[idx + 1]
        
        explanation['analysis'] = "Cette règle sera ajoutée à la configuration iptables."
        explanation['risks'].append("Risque de se bloquer l'accès SSH si vous êtes en connexion distante")
        explanation['recommendations'].append("Tester la règle sur un système de test avant production")
        explanation['recommendations'].append("Sauvegarder la configuration: iptables-save > backup.rules")
        
        return explanation
    
    def analyze_results(self, output: str, parameters: Dict) -> Dict:
        """Analyse les résultats iptables"""
        return {
            'analysis': 'Analyse des règles iptables effectuée',
            'risks': [],
            'recommendations': []
        }

