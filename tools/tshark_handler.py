#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import os
import uuid
import requests
from datetime import datetime
from typing import Dict, List
from .base_handler import BaseHandler


class TsharkHandler(BaseHandler):
    
    def __init__(self, simulation_mode: bool = False, auto_install: bool = True):
        super().__init__("tshark", simulation_mode=simulation_mode, auto_install=auto_install)
        self.captures_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "captures")
        if not os.path.exists(self.captures_dir):
            os.makedirs(self.captures_dir)
    
    def _generate_filename(self) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_id = str(uuid.uuid4())[:8]
        return f"capture_{timestamp}_{unique_id}.pcap"
    
    def generate_command(self, instruction: str, parameters: Dict) -> List[str]:
        cmd = ["tshark"]
        instruction_lower = instruction.lower()
        
        filename = self._generate_filename()
        filepath = os.path.join(self.captures_dir, filename)
        
        cmd.extend(["-w", filepath])
        
        if "interface" in instruction_lower or "eth" in instruction_lower or "wlan" in instruction_lower:
            if_match = re.search(r'(eth\d+|wlan\d+|any|enp\d+|ens\d+)', instruction_lower)
            if if_match:
                cmd.extend(["-i", if_match.group()])
        else:
            cmd.extend(["-i", "any"])
        
        if 'protocol' in parameters:
            protocol = parameters['protocol'].upper()
            if protocol == 'DNS':
                cmd.extend(["-f", "udp port 53"])
            elif protocol == 'HTTP':
                cmd.extend(["-f", "tcp port 80"])
            elif protocol == 'HTTPS':
                cmd.extend(["-f", "tcp port 443"])
            elif protocol == 'SSH':
                cmd.extend(["-f", "tcp port 22"])
            else:
                cmd.extend(["-f", protocol.lower()])
        elif "dns" in instruction_lower:
            cmd.extend(["-f", "udp port 53"])
        elif "http" in instruction_lower:
            cmd.extend(["-f", "tcp port 80"])
        elif "https" in instruction_lower:
            cmd.extend(["-f", "tcp port 443"])
        elif "ssh" in instruction_lower:
            cmd.extend(["-f", "tcp port 22"])
        
        if 'port' in parameters:
            if '-f' not in cmd:
                cmd.extend(["-f", f"port {parameters['port']}"])
            else:
                idx = cmd.index("-f")
                cmd[idx + 1] = f"{cmd[idx + 1]} and port {parameters['port']}"
        
        if 'duration' in parameters:
            try:
                duration_str = str(parameters['duration']).strip()
                duration = int(re.sub(r'[^\d]', '', duration_str))
                cmd.extend(["-a", f"duration:{duration}"])
            except (ValueError, TypeError):
                pass
        elif "seconde" in instruction_lower or "secondes" in instruction_lower or "sec" in instruction_lower:
            time_match = re.search(r'(\d+)\s*(?:seconde|secondes|sec|s)', instruction_lower)
            if time_match:
                try:
                    duration = int(time_match.group(1))
                    cmd.extend(["-a", f"duration:{duration}"])
                except (ValueError, TypeError):
                    pass
        
        if "paquet" in instruction_lower or "packet" in instruction_lower:
            count_match = re.search(r'(\d+)\s*(?:paquet|packet)', instruction_lower)
            if count_match:
                cmd.extend(["-c", count_match.group(1)])
        
        cmd.append("-q")
        
        return cmd
    
    def execute(self, instruction: str, parameters: Dict) -> Dict:
        try:
            cmd = self.generate_command(instruction, parameters)
            
            filepath = None
            for i, arg in enumerate(cmd):
                if arg == "-w" and i + 1 < len(cmd):
                    filepath = cmd[i + 1]
                    break
            
            if not filepath:
                filename = self._generate_filename()
                filepath = os.path.join(self.captures_dir, filename)
                cmd.extend(["-w", filepath])
            
            result = self._run_command(cmd, requires_sudo=True)
            
            if result['success']:
                output = result['output']
                file_size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
                
                pcap_analysis = self._analyze_pcap_file(filepath)
                
                summary = {
                    'summary': f"Capture terminee et sauvegardee dans: {filepath}",
                    'details': {
                        'Fichier': filepath,
                        'Taille': f"{file_size / 1024:.2f} KB" if file_size > 0 else "0 KB"
                    },
                    'analysis': f"La capture a ete sauvegardee avec succes. Vous pouvez l'analyser avec Wireshark ou tshark."
                }
                
                if pcap_analysis:
                    summary['details'].update(pcap_analysis)
                    summary['analysis'] += f"\n\nAnalyse du fichier pcap:\n{pcap_analysis.get('Analyse', '')}"
                
                iptables_rules = []
                if pcap_analysis and 'Regles_iptables' in pcap_analysis:
                    iptables_rules = pcap_analysis['Regles_iptables']
                
                return {
                    'command': ' '.join(cmd),
                    'summary': summary['summary'],
                    'details': summary['details'],
                    'raw_output': output[:500] + "..." if len(output) > 500 else output,
                    'analysis': summary['analysis'],
                    'file_path': filepath,
                    'pcap_analysis': pcap_analysis,
                    'iptables_rules': iptables_rules,
                    'requires_sudo': True,
                    'simulated': result.get('simulated', False),
                    'success': True
                }
            else:
                return {
                    'command': ' '.join(cmd),
                    'error': result.get('error'),
                    'requires_sudo': True,
                    'simulated': result.get('simulated', False),
                    'warning': 'tshark necessite des privileges root'
                }
        except Exception as e:
            return {
                'command': ' '.join(cmd) if 'cmd' in locals() else 'N/A',
                'error': str(e),
                'requires_sudo': True,
                'simulated': self.simulation_mode
            }
    
    def _analyze_pcap_file(self, filepath: str) -> Dict:
        if not os.path.exists(filepath):
            return {}
        
        analysis_info = {}
        
        try:
            packet_count = self._count_packets(filepath)
            if packet_count > 0:
                analysis_info['Paquets_captures'] = str(packet_count)
            
            protocols_cmd = [self.tool_path or "tshark", "-r", filepath, "-q", "-z", "protocols"]
            protocols_result = self._run_command(protocols_cmd, requires_sudo=False)
            
            if protocols_result.get('success') and protocols_result.get('output'):
                analysis_info['Protocoles'] = protocols_result['output'][:600]
            
            stats_cmd = [self.tool_path or "tshark", "-r", filepath, "-q", "-z", "io,stat,0"]
            stats_result = self._run_command(stats_cmd, requires_sudo=False)
            
            if stats_result.get('success') and stats_result.get('output'):
                analysis_info['Statistiques'] = stats_result['output'][:600]
            
            suspicious_ips = []
            top_talkers_cmd = [self.tool_path or "tshark", "-r", filepath, "-q", "-z", "conv,ip"]
            top_result = self._run_command(top_talkers_cmd, requires_sudo=False)
            
            if top_result.get('success') and top_result.get('output'):
                analysis_info['Conversations_IP'] = top_result['output'][:800]
                suspicious_ips = self._detect_suspicious_ips(top_result['output'])
            
            endpoints_cmd = [self.tool_path or "tshark", "-r", filepath, "-q", "-z", "endpoints,ip"]
            endpoints_result = self._run_command(endpoints_cmd, requires_sudo=False)
            
            if endpoints_result.get('success') and endpoints_result.get('output'):
                analysis_info['Endpoints_IP'] = endpoints_result['output'][:800]
                if not suspicious_ips:
                    suspicious_ips = self._detect_suspicious_ips(endpoints_result['output'])
            
            if suspicious_ips:
                ip_info = self._get_ip_info(suspicious_ips)
                if ip_info:
                    analysis_info['IPs_suspectes'] = ip_info
            
            ddos_ips = self._detect_ddos_ips(top_result.get('output', '') + endpoints_result.get('output', ''))
            if ddos_ips:
                analysis_info['IPs_DDoS'] = ddos_ips
                iptables_rules = self._generate_iptables_rules(ddos_ips)
                if iptables_rules:
                    analysis_info['Regles_iptables'] = iptables_rules
            
            http_cmd = [self.tool_path or "tshark", "-r", filepath, "-q", "-z", "http,tree"]
            http_result = self._run_command(http_cmd, requires_sudo=False)
            
            if http_result.get('success') and http_result.get('output'):
                analysis_info['Trafic_HTTP'] = http_result['output'][:600]
            
            dns_cmd = [self.tool_path or "tshark", "-r", filepath, "-q", "-z", "dns,tree"]
            dns_result = self._run_command(dns_cmd, requires_sudo=False)
            
            if dns_result.get('success') and dns_result.get('output'):
                analysis_info['Requetes_DNS'] = dns_result['output'][:600]
            
        except Exception as e:
            pass
        
        return analysis_info
    
    def _count_packets(self, filepath: str) -> int:
        try:
            count_cmd = [self.tool_path or "tshark", "-r", filepath, "-q", "-z", "io,stat,0"]
            result = self._run_command(count_cmd, requires_sudo=False)
            if result.get('success') and result.get('output'):
                output = result['output']
                lines = output.split('\n')
                for line in lines:
                    if 'packets' in line.lower() or 'frames' in line.lower():
                        numbers = re.findall(r'\d+', line)
                        if numbers:
                            try:
                                return int(numbers[0])
                            except:
                                pass
        except:
            pass
        return 0
    
    def _detect_suspicious_ips(self, output: str) -> List[str]:
        suspicious_ips = []
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        lines = output.split('\n')
        
        ip_volumes = {}
        for line in lines:
            ips = re.findall(ip_pattern, line)
            if ips and any(char.isdigit() for char in line):
                numbers = re.findall(r'\d+', line)
                if numbers:
                    try:
                        volume = int(numbers[-1])
                        for ip in ips:
                            if ip not in ['0.0.0.0', '127.0.0.1', '255.255.255.255']:
                                if ip not in ip_volumes:
                                    ip_volumes[ip] = 0
                                ip_volumes[ip] += volume
                    except:
                        pass
        
        if ip_volumes:
            avg_volume = sum(ip_volumes.values()) / len(ip_volumes)
            threshold = avg_volume * 2
            ddos_threshold = avg_volume * 10
            
            for ip, volume in ip_volumes.items():
                if volume > threshold and volume > 100:
                    suspicious_ips.append(ip)
        
        return suspicious_ips[:5]
    
    def _detect_ddos_ips(self, output: str) -> List[Dict[str, int]]:
        ddos_ips = []
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        lines = output.split('\n')
        
        ip_volumes = {}
        for line in lines:
            ips = re.findall(ip_pattern, line)
            if ips and any(char.isdigit() for char in line):
                numbers = re.findall(r'\d+', line)
                if numbers:
                    try:
                        volume = int(numbers[-1])
                        for ip in ips:
                            if ip not in ['0.0.0.0', '127.0.0.1', '255.255.255.255']:
                                if ip not in ip_volumes:
                                    ip_volumes[ip] = 0
                                ip_volumes[ip] += volume
                    except:
                        pass
        
        if ip_volumes:
            avg_volume = sum(ip_volumes.values()) / len(ip_volumes)
            ddos_threshold = max(avg_volume * 10, 1000)
            
            for ip, volume in ip_volumes.items():
                if volume > ddos_threshold:
                    ddos_ips.append({'ip': ip, 'volume': volume})
        
        return sorted(ddos_ips, key=lambda x: x['volume'], reverse=True)[:3]
    
    def _get_ip_info(self, ips: List[str]) -> Dict[str, Dict[str, str]]:
        ip_info = {}
        for ip in ips:
            try:
                response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    ip_info[ip] = {
                        'Fournisseur': data.get('org', 'Inconnu'),
                        'Ville': data.get('city', 'Inconnue')
                    }
            except:
                pass
        return ip_info
    
    def _generate_iptables_rules(self, ddos_ips: List[Dict[str, int]]) -> List[str]:
        rules = []
        for ip_data in ddos_ips:
            ip = ip_data['ip']
            volume = ip_data['volume']
            rule = f"iptables -A INPUT -s {ip} -j DROP"
            rules.append(f"{rule}  # Blocage IP DDoS: {ip} (volume: {volume} paquets)")
        return rules
    
    def analyze_results(self, output: str, parameters: Dict) -> Dict:
        return {
            'analysis': 'Capture reseau effectuee et sauvegardee',
            'risks': [],
            'recommendations': []
        }

