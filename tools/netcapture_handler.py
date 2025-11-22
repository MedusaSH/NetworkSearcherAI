#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Handler pour l'outil tcpdump (capture réseau)
"""

import re
from typing import Dict, List
from .base_handler import BaseHandler


class NetcaptureHandler(BaseHandler):
    """Handler pour l'outil tcpdump"""
    
    def __init__(self, simulation_mode: bool = False, auto_install: bool = True):
        super().__init__("tcpdump", simulation_mode=simulation_mode, auto_install=auto_install)
    
    def generate_command(self, instruction: str, parameters: Dict) -> List[str]:
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
        """Exécute tcpdump"""
        try:
            cmd = self.generate_command(instruction, parameters)
            explanation = self._explain_capture(cmd, instruction, parameters)
            
            if 'duration' in parameters or 'seconde' in instruction.lower():
                duration = int(parameters.get('duration', 10))
                result = self._run_command(cmd, requires_sudo=True)
                
                if result['success']:
                    output = result['output']
                    summary = self._parse_tcpdump_output(output)
                    
                    return {
                        'command': ' '.join(cmd),
                        'summary': summary['summary'],
                        'details': summary['details'],
                        'raw_output': output[:1000] + "..." if len(output) > 1000 else output,
                        'analysis': summary['analysis'],
                        'requires_sudo': True,
                        'simulated': result.get('simulated', False)
                    }
                else:
                    return {
                        'command': ' '.join(cmd),
                        'summary': explanation['summary'],
                        'details': explanation['details'],
                        'error': result.get('error'),
                        'analysis': explanation['analysis'],
                        'requires_sudo': True,
                        'simulated': result.get('simulated', False),
                        'warning': 'tcpdump necessite des privileges root'
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
                    'simulated': self.simulation_mode,
                    'warning': 'Cette commande necessite sudo'
                }
        except Exception as e:
            return {
                'command': ' '.join(cmd) if 'cmd' in locals() else 'N/A',
                'error': str(e),
                'requires_sudo': True,
                'simulated': self.simulation_mode
            }
    
    def _explain_capture(self, cmd: List[str], instruction: str, parameters: Dict) -> Dict:
        """Explique ce que fait la commande tcpdump"""
        explanation = {
            'summary': f"Commande tcpdump générée pour: {instruction}",
            'details': {},
            'analysis': '',
            'risks': [],
            'recommendations': []
        }
        
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
        
        explanation['analysis'] = "Cette commande capturera le trafic réseau selon les filtres spécifiés."
        explanation['risks'].append("La capture de trafic peut contenir des données sensibles")
        explanation['risks'].append("Assurez-vous d'avoir l'autorisation légale")
        explanation['recommendations'].append("Analyser le fichier .pcap avec Wireshark")
        explanation['recommendations'].append("Limiter la durée de capture")
        
        return explanation
    
    def _parse_tcpdump_output(self, output: str) -> Dict:
        """Parse la sortie de tcpdump"""
        summary = {'summary': '', 'details': {}, 'analysis': ''}
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
        
        summary['analysis'] = f"Analyse: {packet_count} paquet(s), protocoles: {', '.join(protocols.keys()) if protocols else 'N/A'}"
        
        return summary
    
    def analyze_results(self, output: str, parameters: Dict) -> Dict:
        """Analyse les résultats de capture"""
        return {
            'analysis': 'Analyse du trafic réseau effectuée',
            'risks': [],
            'recommendations': []
        }

