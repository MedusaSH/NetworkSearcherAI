#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
import os
import socket
from typing import Dict, Optional
from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.live import Live
from rich.markdown import Markdown
from rich.syntax import Syntax
from rich.style import Style

from core.parsing import CommandParser
from core.dispatcher import CommandDispatcher


class AnimatedCLI:
    
    def __init__(self, claude_api_key: str = None, simulation_mode: bool = False, auto_install: bool = True):
        self.console = Console()
        self.parser = CommandParser(claude_api_key=claude_api_key)
        self.dispatcher = CommandDispatcher(simulation_mode=simulation_mode, auto_install=auto_install, claude_api_key=claude_api_key)
        self.simulation_mode = simulation_mode
        self.auto_install = auto_install
        self.claude_api_key = claude_api_key
        
        self.colors = {
            'primary': '#8B5CF6',
            'secondary': '#A78BFA',
            'accent': '#C4B5FD',
            'text': '#E9D5FF',
            'text_dim': '#C4B5FD',
            'success': '#A78BFA',
            'warning': '#C4B5FD',
            'error': '#F59E0B',
            'info': '#A78BFA'
        }
    
    def _type_text(self, text: str, delay: float = 0.02, color: str = None, bold: bool = False):
        YELLOW = '\033[93m'
        RESET = '\033[0m'
        bold_code = '\033[1m' if bold else ''
        for char in text:
            if char == '\n':
                print()
            else:
                print(f"{YELLOW}{bold_code}{char}{RESET}", end='', flush=True)
                time.sleep(delay)
        if not text.endswith('\n'):
            print()
    
    def _print_header(self):
        YELLOW = '\033[93m'
        RESET = '\033[0m'
        
        header = f"""{YELLOW}
("`-''-/").___..--''"`-._ 
 `6_ 6  )   `-.  (     ).`-.__.`)  /* Author : MedusaSH
 (_Y_.)'  ._   )  `._ `. ``-..-' 
   _..`--'_..-_/  /--'_.'
  ((((.-''  ((((.'  (((.-' 
{RESET}"""
        print(header)
        
        if self.simulation_mode:
            print(f"{YELLOW}Mode SIMULATION active{RESET}")
        else:
            print(f"{YELLOW}Mode EXECUTION REELLE{RESET}")
        
        print()
        print(f"{YELLOW}Format: [outil] : [instruction] : [parametres] OR [instruction] : [parametres] ( détéction automatique de l'outil){RESET}")
        print(f"{YELLOW}Exemple:{RESET}")
        print(f"{YELLOW}  - nmap: scan cette IP 192.168.1.1{RESET}")
        print(f"{YELLOW}  - iptables: bloque cette IP 1.2.3.4{RESET}")
        print(f"{YELLOW}  - tshark: capture les paquets pendant 10 secondes{RESET}")
        print(f"{YELLOW}Tapez 'quit' pour quitter{RESET}")
        print()
    
    def _print_prompt(self):
        YELLOW = '\033[93m'
        RESET = '\033[0m'
        print(f"{YELLOW}> {RESET}", end='', flush=True)
    
    def _format_output_animated(self, command: str, result: Dict):
        print()
        
        if result.get('error'):
            error_text = result.get('raw_output') or result['error']
            self._type_text("Erreur:", delay=0.02)
            self._type_text(error_text, delay=0.01)
        elif result.get('raw_output'):
            output_text = result['raw_output'].strip()
            if output_text:
                self._type_text(output_text, delay=0.005)
            else:
                self._type_text("Commande executee mais aucune sortie", delay=0.02)
        elif result.get('summary'):
            self._type_text(result['summary'], delay=0.02)
            if result.get('details'):
                print()
                for key, value in result['details'].items():
                    key_text = f"{key}: "
                    self._type_text(key_text, delay=0.01)
                    if isinstance(value, dict):
                        print()
                        for k, v in value.items():
                            self._type_text(f"  {k}: {v}", delay=0.01)
                    else:
                        self._type_text(str(value), delay=0.01)
                    print()
        
        if result.get('file_path'):
            print()
            self._type_text("Fichier sauvegarde: ", delay=0.01)
            self._type_text(result['file_path'], delay=0.005)
            print()
        
        if result.get('iptables_rules'):
            print()
            separator = "─" * 80
            self._type_text(separator, delay=0.001)
            self._type_text("DETECTION DDoS - REGLES IPTABLES GENEREES", delay=0.02, bold=True)
            self._type_text(separator, delay=0.001)
            print()
            for rule in result['iptables_rules']:
                self._type_text(rule, delay=0.01)
                print()
            print()
        
        if result.get('claude_explanation'):
            print()
            separator = "─" * 80
            self._type_text(separator, delay=0.001)
            self._type_text("EXPLICATION CLAUDE", delay=0.02, bold=True)
            self._type_text(separator, delay=0.001)
            print()
            
            command = result.get('command', '')
            if command:
                self._type_text("Commande executee: ", delay=0.01)
                self._type_text(command, delay=0.005)
                print()
                print()
            
            explanation = result['claude_explanation']
            self._type_text(explanation, delay=0.01)
            print()
        
        if result.get('warning'):
            print()
            self._type_text(f"ATTENTION: {result['warning']}", delay=0.02)
        
        if result.get('simulated'):
            print()
            self._type_text("Mode simulation - aucune action reelle", delay=0.02)
    
    def _show_loading(self, message: str = "Traitement en cours..."):
        with Progress(
            SpinnerColumn(),
            TextColumn(f"[\033[93m]{message}[\033[0m]"),
            console=self.console,
            transient=True
        ) as progress:
            task = progress.add_task("", total=None)
            time.sleep(0.5)
    
    def _get_welcome_message(self, hostname: str) -> str:
        if not self.claude_api_key:
            return f"Bienvenue {hostname} !\n\nCe systeme orchestre des outils de cybersecurite avec l'IA Claude.\n\nExemples:\n- nmap: 'scan cette IP 192.168.1.1'\n- iptables: 'bloque cette IP 1.2.3.4'\n- tshark: 'capture les paquets pendant 10 secondes'"
        
        try:
            from ai.claude_api import ClaudeAPI
            claude = ClaudeAPI(self.claude_api_key)
            
            system_prompt = f"""Tu es un assistant expert en cybersecurite qui accueille {hostname} dans un systeme d'orchestration d'outils de cybersecurite.

Le systeme permet de:
- Scanner des IPs avec nmap
- Configurer des regles firewall avec iptables
- Capturer du trafic reseau avec tshark

Accueille {hostname} brievement. Donne UN exemple court pour CHAQUE outil:
- nmap: exemple de scan
- iptables: exemple de regle
- tshark: exemple de capture

Sois direct et concis. Maximum 3-4 phrases. Pas de discussion, juste les faits."""

            messages = [
                {
                    "role": "user",
                    "content": f"Accueille {hostname} et donne un exemple pour chaque outil."
                }
            ]
            
            response = claude._make_request(messages, system=system_prompt, max_tokens=150)
            
            if "error" not in response and "content" in response:
                content = response.get("content", [])
                if content and len(content) > 0:
                    text = content[0].get("text", "")
                    if text:
                        return text
            
            return f"Bienvenue {hostname} !\n\nCe systeme orchestre des outils de cybersecurite avec l'IA Claude.\n\nExemples:\n- nmap: 'scan cette IP 192.168.1.1'\n- iptables: 'bloque cette IP 1.2.3.4'\n- tshark: 'capture les paquets pendant 10 secondes'"
        except:
            return f"Bienvenue {hostname} !\n\nCe systeme orchestre des outils de cybersecurite avec l'IA Claude.\n\nExemples:\n- nmap: 'scan cette IP 192.168.1.1'\n- iptables: 'bloque cette IP 1.2.3.4'\n- tshark: 'capture les paquets pendant 10 secondes'"
    
    def run_interactive(self):
        os.system('clear' if os.name != 'nt' else 'cls')
        
        hostname = os.environ.get('COMPUTERNAME') or os.environ.get('HOSTNAME') or socket.gethostname()
        
        self._print_header()
        
        welcome_msg = self._get_welcome_message(hostname)
        self.console.print()
        YELLOW = '\033[93m'
        RESET = '\033[0m'
        for char in welcome_msg:
            print(f"{YELLOW}{char}{RESET}", end='', flush=True)
            time.sleep(0.01)
        print()
        print()
        
        while True:
            try:
                self._print_prompt()
                user_input = input().strip()
                
                if user_input.lower() in ['quit', 'exit', 'q']:
                    self._type_text("Au revoir !", delay=0.03)
                    break
                
                if not user_input:
                    continue
                
                self._show_loading("Analyse de la commande avec Claude...")
                
                parsed = self.parser.parse(user_input)
                
                if parsed.tool.value == "unknown":
                    self._type_text(f"Outil non reconnu: {user_input}", delay=0.02)
                    print()
                    continue
                
                self._show_loading("Execution de la commande...")
                
                result = self.dispatcher.dispatch(parsed)
                
                if not result:
                    self._type_text("Aucun resultat retourne", delay=0.02)
                    print()
                    continue
                
                self._format_output_animated(user_input, result)
                print()
                
            except (EOFError, KeyboardInterrupt):
                print()
                self._type_text("\nAu revoir !", delay=0.03)
                break
            except Exception as e:
                self._type_text(f"Erreur: {e}", delay=0.02)
                print()
    
    def run_command(self, user_input: str):
        try:
            self._show_loading("Analyse avec Claude...")
            parsed = self.parser.parse(user_input)
            
            if parsed.tool.value == "unknown":
                self._type_text(f"Outil non reconnu: {user_input}", delay=0.02)
                return
            
            self._show_loading("Execution...")
            result = self.dispatcher.dispatch(parsed)
            
            if not result:
                self._type_text("Aucun resultat", delay=0.02)
                return
            
            if result.get('simulated'):
                self._type_text("ATTENTION: Mode simulation active - commande non executee", delay=0.02)
                print()
            
            self._format_output_animated(user_input, result)
        except Exception as e:
            self._type_text(f"Erreur: {e}", delay=0.02)
            import traceback
            traceback.print_exc()
