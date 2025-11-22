#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import sys
import os
import shutil
from typing import Dict, Tuple, Optional


class PackageManager:
    
    def __init__(self):
        self.tools = {
            'nmap': {
                'linux': ['apt-get', 'install', '-y', 'nmap'],
                'darwin': ['brew', 'install', 'nmap'],
                'windows': ['choco', 'install', 'nmap', '-y'],
                'check_cmd': ['nmap', '--version']
            },
            'iptables': {
                'linux': None,
                'darwin': None,
                'windows': None,
                'check_cmd': ['iptables', '--version']
            },
            'dig': {
                'linux': ['apt-get', 'install', '-y', 'dnsutils'],
                'darwin': ['brew', 'install', 'bind'],
                'windows': ['choco', 'install', 'bind-toolsonly', '-y'],
                'check_cmd': ['dig', '-v']
            },
            'whois': {
                'linux': ['apt-get', 'install', '-y', 'whois'],
                'darwin': ['brew', 'install', 'whois'],
                'windows': ['choco', 'install', 'whois', '-y'],
                'check_cmd': ['whois', '--version']
            },
            'tcpdump': {
                'linux': ['apt-get', 'install', '-y', 'tcpdump'],
                'darwin': ['brew', 'install', 'tcpdump'],
                'windows': ['choco', 'install', 'tcpdump', '-y'],
                'check_cmd': ['tcpdump', '--version']
            },
            'tshark': {
                'linux': ['apt-get', 'install', '-y', 'tshark'],
                'darwin': ['brew', 'install', 'wireshark'],
                'windows': ['choco', 'install', 'wireshark', '-y'],
                'check_cmd': ['tshark', '--version']
            }
        }
        
        self.platform = sys.platform
        self.is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
    
    def is_installed(self, tool_name: str) -> bool:
        return shutil.which(tool_name) is not None
    
    def install_tool(self, tool_name: str) -> Tuple[bool, str]:
        if tool_name not in self.tools:
            return (False, f"Outil {tool_name} non supporte pour l'installation automatique")
        
        if self.is_installed(tool_name):
            return (True, f"{tool_name} est deja installe")
        
        tool_info = self.tools[tool_name]
        
        if self.platform.startswith('linux'):
            install_cmd = tool_info.get('linux')
            use_sudo = True
        elif self.platform == 'darwin':
            install_cmd = tool_info.get('darwin')
            use_sudo = False
        elif self.platform == 'win32':
            install_cmd = tool_info.get('windows')
            use_sudo = False
        else:
            return (False, f"Plateforme {self.platform} non supportee")
        
        if install_cmd is None:
            return (False, f"{tool_name} n'est pas disponible pour installation automatique sur cette plateforme")
        
        if use_sudo and not self.is_root:
            full_cmd = ['sudo'] + install_cmd
        else:
            full_cmd = install_cmd
        
        try:
            print(f"Installation de {tool_name}...", flush=True)
            if use_sudo and not self.is_root:
                print("ATTENTION: sudo peut demander votre mot de passe", flush=True)
            
            result = subprocess.run(
                full_cmd,
                capture_output=False,
                text=True,
                timeout=300,
                check=False
            )
            
            if result.returncode == 0:
                if self.is_installed(tool_name):
                    return (True, f"{tool_name} installe avec succes")
                else:
                    return (False, f"Installation terminee mais {tool_name} n'est pas dans le PATH")
            else:
                error_msg = result.stderr or result.stdout or "Erreur inconnue"
                return (False, f"Erreur lors de l'installation: {error_msg}")
        
        except subprocess.TimeoutExpired:
            return (False, "Timeout lors de l'installation")
        except FileNotFoundError:
            if 'apt-get' in full_cmd:
                return (False, "apt-get n'est pas disponible. Installez manuellement avec: sudo apt-get install")
            elif 'brew' in full_cmd:
                return (False, "Homebrew n'est pas installe. Installez-le depuis https://brew.sh")
            elif 'choco' in full_cmd:
                return (False, "Chocolatey n'est pas installe. Installez-le depuis https://chocolatey.org")
            else:
                return (False, "Gestionnaire de paquets non trouve")
        except Exception as e:
            return (False, f"Erreur: {str(e)}")
    
    def ensure_installed(self, tool_name: str, auto_install: bool = True) -> Tuple[bool, str]:
        if self.is_installed(tool_name):
            return (True, f"{tool_name} est disponible")
        
        if not auto_install:
            return (False, f"{tool_name} n'est pas installe. Installez-le manuellement.")
        
        success, message = self.install_tool(tool_name)
        return (success, message)
