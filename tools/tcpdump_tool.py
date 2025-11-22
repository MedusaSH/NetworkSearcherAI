#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module pour l'outil tcpdump
"""

import re
from typing import Dict
from .base_tool import BaseTool


class TcpdumpTool(BaseTool):
    """Gestionnaire pour l'outil tcpdump"""
    
    def __init__(self):
        super().__init__("tcpdump")
    
    def generate_command(self, instruction: str, parameters: Dict) -> list:
        """Génère la commande tcpdump"""
        cmd = ["tcpdump"]
        
        instruction_lower = instruction.lower()
        
        if "interface" in instruction_lower or "eth" in instruction_lower:
            if_match = re.search(r'(eth\d+|wlan\d+|any)', instruction_lower)
            if if_match:
                cmd.extend(["-i", if_match.group()])
        else:
            cmd.extend(["-i", "any"])  
        
        if 'protocol' in parameters:
            protocol = parameters['protocol'].upper()
            if protocol == 'DNS':
                cmd.append("udp port 53")
            elif protocol == 'HTTP':
                cmd.append("tcp port 80")
            elif protocol == 'HTTPS':
                cmd.append("tcp port 443")
            elif protocol == 'SSH':
                cmd.append("tcp port 22")
            else:
                cmd.append(protocol.lower())
        elif "dns" in instruction_lower:
            cmd.append("udp port 53")
        elif "http" in instruction_lower:
            cmd.append("tcp port 80")
        elif "https" in instruction_lower:
            cmd.append("tcp port 443")
        elif "ssh" in instruction_lower:
            cmd.append("tcp port 22")
        
        if 'port' in parameters:
            if 'protocol' not in parameters:
                cmd.append(f"port {parameters['port']}")
        
        if 'duration' in parameters:
            duration = int(parameters['duration'])
            cmd.extend(["-G", str(duration), "-W", "1"])  
        elif "seconde" in instruction_lower or "secondes" in instruction_lower:
            time_match = re.search(r'(\d+)\s*(?:seconde|secondes|sec|s)', instruction_lower)
            if time_match:
                duration = int(time_match.group(1))
                cmd.extend(["-G", str(duration), "-W", "1"])
        
        if "paquet" in instruction_lower or "packet" in instruction_lower:
            count_match = re.search(r'(\d+)\s*(?:paquet|packet)', instruction_lower)
            if count_match:
                cmd.extend(["-c", count_match.group(1)])
        
        cmd.append("-n")  
        cmd.append("-v")  
        
        if "fichier" in instruction_lower or "file" in instruction_lower or "pcap" in instruction_lower:
            filename_match = re.search(r'(?:fichier|file|pcap).*?([\w\.-]+)', instruction_lower)
            if filename_match:
                filename = filename_match.group(1)
                if not filename.endswith('.pcap'):
                    filename += '.pcap'
                cmd.extend(["-w", filename])
            else:
                cmd.extend(["-w", "capture.pcap"])
        
        return cmd
    
    def execute(self, instruction: str, parameters: Dict) -> Dict:
        """Exécute tcpdump et analyse les résultats"""
        try:
            cmd = self.generate_command(instruction, parameters)
            
            explanation = self._explain_capture(cmd, instruction, parameters)
            
            if 'duration' in parameters or 'seconde' in instruction.lower():
                duration = int(parameters.get('duration', 10))
                result = self._run_command(cmd, requires_sudo=True, capture_output=True)
                
                if result['success']:
                    output = result['output']
                    summary = self._parse_tcpdump_output(output)
                    
                    return {
                        'command': ' '.join(cmd),
                        'summary': summary['summary'],
                        'details': summary['details'],
                        'raw_output': output[:1000] + "..." if len(output) > 1000 else output,
                        'analysis': summary['analysis'],
                        'requires_sudo': True
                    }
                else:
                    return {
                        'command': ' '.join(cmd),
                        'summary': explanation['summary'],
                        'details': explanation['details'],
                        'error': result['error'] or "Impossible d'exécuter tcpdump (nécessite sudo)",
                        'analysis': explanation['analysis'],
                        'requires_sudo': True,
                        'warning': '⚠️  tcpdump nécessite des privilèges root pour capturer le trafic réseau'
                    }
            else:
                return {
                    'command': ' '.join(cmd),
                    'summary': explanation['summary'],
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
    
    def _explain_capture(self, cmd: list, instruction: str, parameters: Dict) -> Dict:
        """Explique ce que fait la commande tcpdump"""
        explanation = {
            'summary': '',
            'details': {},
            'analysis': '',
            'risks': [],
            'recommendations': []
        }
        
        explanation['summary'] = f"Commande tcpdump générée pour: {instruction}"
        
        if "-i" in cmd:
            idx = cmd.index("-i")
            if idx + 1 < len(cmd):
                explanation['details']['Interface'] = cmd[idx + 1]
        
        protocol_parts = [p for p in cmd if 'port' in p or p in ['tcp', 'udp', 'icmp']]
        if protocol_parts:
            explanation['details']['Filtre'] = ' '.join(protocol_parts)
        
        if "-G" in cmd:
            idx = cmd.index("-G")
            if idx + 1 < len(cmd):
                explanation['details']['Durée'] = f"{cmd[idx + 1]} secondes"
        
        if "-w" in cmd:
            idx = cmd.index("-w")
            if idx + 1 < len(cmd):
                explanation['details']['Fichier de sortie'] = cmd[idx + 1]
        
        explanation['analysis'] = "Cette commande capturera le trafic réseau selon les filtres spécifiés. " \
                                 "Les paquets seront affichés en temps réel ou sauvegardés dans un fichier."
        
        explanation['risks'].append("La capture de trafic peut contenir des données sensibles (mots de passe, etc.)")
        explanation['risks'].append("Assurez-vous d'avoir l'autorisation légale pour capturer le trafic")
        
        explanation['recommendations'].append("Analyser le fichier .pcap avec Wireshark pour une analyse approfondie")
        explanation['recommendations'].append("Limiter la durée de capture pour éviter les fichiers trop volumineux")
        explanation['recommendations'].append("Utiliser des filtres précis pour ne capturer que le trafic nécessaire")
        
        return explanation
    
    def _parse_tcpdump_output(self, output: str) -> Dict:
        """Parse la sortie de tcpdump"""
        summary = {
            'summary': '',
            'details': {},
            'analysis': ''
        }
        
        lines = output.split('\n')
        packet_count = len([l for l in lines if l.strip() and not l.startswith('listening')])
        
        summary['summary'] = f"Capture terminée: {packet_count} paquet(s) capturé(s)"
        
        protocols = {}
        for line in lines:
            if 'IP' in line:
                if 'TCP' in line:
                    protocols['TCP'] = protocols.get('TCP', 0) + 1
                elif 'UDP' in line:
                    protocols['UDP'] = protocols.get('UDP', 0) + 1
                elif 'ICMP' in line:
                    protocols['ICMP'] = protocols.get('ICMP', 0) + 1
        
        if protocols:
            summary['details']['Protocoles'] = ', '.join([f"{k}: {v}" for k, v in protocols.items()])
        
        summary['analysis'] = f"Analyse du trafic: {packet_count} paquet(s) analysé(s). " \
                             f"Distribution des protocoles: {', '.join(protocols.keys()) if protocols else 'N/A'}"
        
        return summary

