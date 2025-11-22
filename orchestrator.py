#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from interfaces.cli_animated import AnimatedCLI


YELLOW = '\033[93m'
RESET = '\033[0m'

def load_config():
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
    
    if not os.path.exists(config_path):
        print(f"{YELLOW}ERREUR: Le fichier config.json n'existe pas.{RESET}")
        print(f"{YELLOW}Creer un fichier config.json avec la structure suivante:{RESET}")
        print(f"{YELLOW}{json.dumps({'claude_api_key': 'votre_cle_api_ici'}, indent=2)}{RESET}")
        return None
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        api_key = config.get("claude_api_key")
        if not api_key:
            print(f"{YELLOW}ERREUR: La cle 'claude_api_key' est manquante dans config.json{RESET}")
            return None
        
        return api_key
    except json.JSONDecodeError as e:
        print(f"{YELLOW}ERREUR: Le fichier config.json est invalide: {e}{RESET}")
        return None
    except Exception as e:
        print(f"{YELLOW}ERREUR lors de la lecture de config.json: {e}{RESET}")
        return None


def print_help():
    YELLOW = '\033[93m'
    RESET = '\033[0m'
    
    help_text = f"""{YELLOW}
 ("`-''-/").___..--''"`-._ 
  `6_ 6  )   `-.  (     ).`-.__.`) /* Author : MedusaSH */
  (_Y_.)'  ._   )  `._ `. ``-..-' 
    _..`--'_..-_/  /--'_.'
   ((((.-''  ((((.'  (((.-' 

ORCHESTRATEUR DE CYBERSECURITE AVEC IA CLAUDE
Outils: nmap (scan), iptables (firewall), tshark (capture trafic)
Usage: python3 orchestrator.py --interactive | python3 orchestrator.py "commande"
Exemples: "scan cette IP 192.168.1.1" | "capture les paquets pendant 10 secondes" | "bloque cette IP 1.2.3.4"
Options: --interactive (-i) mode interactif | --simulate (--sim) mode simulation | --help (-h) aide{RESET}"""
    print(help_text)


def main():
    if '--help' in sys.argv or '-h' in sys.argv:
        print_help()
        return
    
    claude_api_key = load_config()
    
    if not claude_api_key:
        print(f"{YELLOW}Le systeme fonctionnera sans Claude API (mode fallback){RESET}")
        claude_api_key = None
    
    simulation_mode = False
    
    if '--simulate' in sys.argv or '--sim' in sys.argv:
        simulation_mode = True
        sys.argv.remove('--simulate') if '--simulate' in sys.argv else sys.argv.remove('--sim')
    
    cli = AnimatedCLI(claude_api_key=claude_api_key, simulation_mode=simulation_mode, auto_install=True)
    
    if '--interactive' in sys.argv or '-i' in sys.argv:
        sys.argv.remove('--interactive') if '--interactive' in sys.argv else sys.argv.remove('-i')
        cli.run_interactive()
    elif len(sys.argv) > 1:
        user_input = " ".join(sys.argv[1:])
        cli.run_command(user_input)
    else:
        print_help()
        print(f"{YELLOW}\n" + "="*80 + f"{RESET}")
        print(f"{YELLOW}Pour lancer le mode interactif, utilisez: python3 orchestrator.py --interactive{RESET}")
        print(f"{YELLOW}" + "="*80 + f"\n{RESET}")


if __name__ == "__main__":
    main()
