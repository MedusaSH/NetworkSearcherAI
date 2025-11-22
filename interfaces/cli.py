#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from typing import Dict
from core.parsing import CommandParser
from core.dispatcher import CommandDispatcher


class CLIInterface:
    
    def __init__(self, simulation_mode: bool = True):
        self.parser = CommandParser()
        self.dispatcher = CommandDispatcher(simulation_mode=simulation_mode)
        self.simulation_mode = simulation_mode
    
    def format_output(self, command: str, result: Dict) -> str:
        output = []
        
        if result.get('error'):
            if result.get('raw_output'):
                output.append(result['raw_output'].strip())
            else:
                output.append(result['error'])
        elif result.get('raw_output'):
            output.append(result['raw_output'].strip())
        elif result.get('summary'):
            output.append(result['summary'])
            if result.get('details'):
                for key, value in result['details'].items():
                    if isinstance(value, dict):
                        output.append(f"\n{key}:")
                        for k, v in value.items():
                            output.append(f"  {k}: {v}")
                    else:
                        output.append(f"{key}: {value}")
        else:
            output.append("Aucun resultat disponible")
        
        has_analysis = result.get('analysis') or result.get('risks') or result.get('recommendations')
        if has_analysis:
            output.append("")
            output.append("─" * 80)
            output.append("ANALYSE")
            output.append("─" * 80)
            
            if result.get('analysis'):
                output.append(result['analysis'])
            
            if result.get('risks'):
                output.append("")
                output.append("Risques identifies:")
                for risk in result['risks']:
                    output.append(f"  - {risk}")
            
            if result.get('recommendations'):
                output.append("")
                output.append("Recommandations:")
                for rec in result['recommendations']:
                    output.append(f"  - {rec}")
        
        if result.get('warning'):
            output.append("")
            output.append(f"ATTENTION: {result['warning']}")
        
        if result.get('simulated'):
            output.append("")
            output.append("Mode simulation active - aucune action reelle effectuee")
        
        return "\n".join(output)
    
    def run_interactive(self):
        print("Orchestrateur d'outils de cybersecurite")
        if self.simulation_mode:
            print("Mode SIMULATION active - aucune action reelle ne sera effectuee")
        else:
            print("Mode EXECUTION REELLE - les commandes seront reellement executees")
        print("Format: [outil] : [instruction] : [parametres] OR [instruction] : [parametres] ( détéction automatique de l'outil)")
        print("Exemple: nmap : je veux analyser tout ce qu'il y a d'utile dans cette IP : 192.168.1.20")
        print("Tapez 'quit' pour quitter\n")
        
        while True:
            try:
                user_input = input("> ").strip()
                if user_input.lower() in ['quit', 'exit', 'q']:
                    break
                if not user_input:
                    continue
                
                parsed = self.parser.parse(user_input)
                result = self.dispatcher.dispatch(parsed)
                output = self.format_output(user_input, result)
                
                print(output)
                print()
            except (EOFError, KeyboardInterrupt):
                break
    
    def run_command(self, user_input: str):
        try:
            parsed = self.parser.parse(user_input)
            if parsed.tool.value == "unknown":
                print(f"Outil non reconnu: {user_input}", flush=True)
                return
            
            result = self.dispatcher.dispatch(parsed)
            if not result:
                print("Aucun resultat retourne", flush=True)
                return
            
            output = self.format_output(user_input, result)
            if output:
                print(output, flush=True)
            else:
                print("Aucune sortie generee", flush=True)
        except Exception as e:
            print(f"Erreur: {e}", flush=True)
            import traceback
            traceback.print_exc()
