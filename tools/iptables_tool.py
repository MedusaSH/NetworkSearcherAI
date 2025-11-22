#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module pour l'outil iptables
"""

import re
from typing import Dict, List
from .base_tool import BaseTool


class IptablesTool(BaseTool):
    """Gestionnaire pour l'outil iptables"""
    
    def __init__(self):
        super().__init__("iptables")
    
    def generate_command(self, instruction: str, parameters: Dict) -> list:
        """Génère la commande iptables"""
        instruction_lower = instruction.lower()
        cmd = ["iptables"]
        
        if "bloque" in instruction_lower or "block" in instruction_lower or "refuse" in instruction_lower:
            action = "-A"  
            target = "DROP"
        elif "autorise" in instruction_lower or "allow" in instruction_lower or "accept" in instruction_lower:
            action = "-A"
            target = "ACCEPT"
        elif "supprime" in instruction_lower or "delete" in instruction_lower:
            action = "-D"
            target = None
        else:
            action = "-A"
            target = "DROP"
        
        if "entrant" in instruction_lower or "input" in instruction_lower or "incoming" in instruction_lower:
            chain = "INPUT"
        elif "sortant" in instruction_lower or "output" in instruction_lower or "outgoing" in instruction_lower:
            chain = "OUTPUT"
        elif "forward" in instruction_lower or "transit" in instruction_lower:
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
            if "source" in instruction_lower or "src" in instruction_lower:
                cmd.extend(["--sport", str(parameters['port'])])
            else:
                cmd.extend(["--dport", str(parameters['port'])])
        
        if 'ip' in parameters:
            if "source" in instruction_lower or "src" in instruction_lower:
                cmd.extend(["-s", parameters['ip']])
            else:
                cmd.extend(["-d", parameters['ip']])
        
        if "sauf" in instruction_lower or "except" in instruction_lower or "excepté" in instruction_lower:
            if "ssh" in instruction_lower:
                ssh_cmd = ["iptables", "-I", chain, "-p", "tcp", "--dport", "22", "-j", "ACCEPT"]
                if target:
                    cmd.append("-j")
                    cmd.append(target)
            else:
                port_match = re.search(r'sauf.*?(\d+)', instruction_lower)
                if port_match:
                    port = port_match.group(1)
                    pass
        
        if "interface" in instruction_lower or "eth" in instruction_lower:
            if_match = re.search(r'(eth\d+|wlan\d+|lo)', instruction_lower)
            if if_match:
                cmd.extend(["-i", if_match.group()])
        
        if target:
            cmd.append("-j")
            cmd.append(target)
        
        return cmd
    
    def execute(self, instruction: str, parameters: Dict) -> Dict:
        """Exécute iptables et analyse les résultats"""
        try:
            cmd = self.generate_command(instruction, parameters)
            
            if "liste" in instruction.lower() or "list" in instruction.lower() or "show" in instruction.lower():
                list_cmd = ["iptables", "-L", "-v", "-n"]
                result = self._run_command(list_cmd, requires_sudo=True)
                
                if not result['success']:
                    return {
                        'command': ' '.join(list_cmd),
                        'error': result['error'] or "Impossible d'exécuter iptables (nécessite sudo)",
                        'requires_sudo': True
                    }
                
                output = result['output']
                summary = self._parse_iptables_list(output)
                
                return {
                    'command': ' '.join(list_cmd),
                    'summary': summary['summary'],
                    'details': summary['details'],
                    'raw_output': output,
                    'analysis': summary['analysis'],
                    'requires_sudo': True
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
                    'warning': '⚠️  Cette commande n\'a PAS été exécutée. Exécutez-la manuellement avec sudo si vous êtes sûr.'
                }
        except Exception as e:
            return {
                'command': ' '.join(cmd) if 'cmd' in locals() else 'N/A',
                'error': str(e),
                'requires_sudo': True
            }
    
    def _parse_iptables_list(self, output: str) -> Dict:
        """Parse la sortie de iptables -L"""
        summary = {
            'summary': '',
            'details': {},
            'analysis': ''
        }
        
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
        summary['summary'] = f"Configuration iptables: {len(chains)} chaîne(s), {rule_count} règle(s) active(s)"
        
        summary['details'] = {
            'Chaînes': ', '.join(chains.keys()),
            'Règles par chaîne': {chain: len(rules) for chain, rules in chains.items()}
        }
        
        summary['analysis'] = f"Analyse des règles: {len(chains.get('INPUT', []))} règle(s) INPUT, " \
                             f"{len(chains.get('OUTPUT', []))} règle(s) OUTPUT, " \
                             f"{len(chains.get('FORWARD', []))} règle(s) FORWARD"
        
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
        elif "-A FORWARD" in ' '.join(cmd):
            explanation['details']['Action'] = "Ajout d'une règle à la chaîne FORWARD"
        
        if "-j DROP" in ' '.join(cmd):
            explanation['details']['Effet'] = "Bloque les paquets correspondants"
        elif "-j ACCEPT" in ' '.join(cmd):
            explanation['details']['Effet'] = "Autorise les paquets correspondants"
        
        if "--dport" in cmd:
            idx = cmd.index("--dport")
            if idx + 1 < len(cmd):
                explanation['details']['Port destination'] = cmd[idx + 1]
        
        if "--sport" in cmd:
            idx = cmd.index("--sport")
            if idx + 1 < len(cmd):
                explanation['details']['Port source'] = cmd[idx + 1]
        
        if "-s" in cmd:
            idx = cmd.index("-s")
            if idx + 1 < len(cmd):
                explanation['details']['IP source'] = cmd[idx + 1]
        
        if "-d" in cmd:
            idx = cmd.index("-d")
            if idx + 1 < len(cmd):
                explanation['details']['IP destination'] = cmd[idx + 1]
        
        explanation['analysis'] = "Cette règle sera ajoutée à la configuration iptables. " \
                                 "Assurez-vous de ne pas vous bloquer vous-même (notamment pour SSH)."
        
        if "-j DROP" in ' '.join(cmd) and "INPUT" in ' '.join(cmd):
            if "--dport 22" not in ' '.join(cmd) and "sauf" not in instruction.lower():
                explanation['risks'].append("Risque de se bloquer l'accès SSH si vous êtes en connexion distante")
        
        explanation['recommendations'].append("Tester la règle sur un système de test avant production")
        explanation['recommendations'].append("Sauvegarder la configuration actuelle: iptables-save > backup.rules")
        explanation['recommendations'].append("Vérifier les règles après application: sudo iptables -L -v -n")
        
        return explanation

