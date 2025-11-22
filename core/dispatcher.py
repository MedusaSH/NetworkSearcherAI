#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Dict, Optional
from core.parsing import ParsedCommand, ToolType

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.nmap_handler import NmapHandler
from tools.iptables_handler import IptablesHandler
from tools.tshark_handler import TsharkHandler


class CommandDispatcher:
    
    def __init__(self, simulation_mode: bool = False, auto_install: bool = True, claude_api_key: str = None):
        self.simulation_mode = simulation_mode
        self.auto_install = auto_install
        self._claude_api_key = claude_api_key
        
        self.handlers = {
            ToolType.NMAP: NmapHandler(simulation_mode=simulation_mode, auto_install=auto_install),
            ToolType.IPTABLES: IptablesHandler(simulation_mode=simulation_mode, auto_install=auto_install),
            ToolType.TSHARK: TsharkHandler(simulation_mode=simulation_mode, auto_install=auto_install),
        }
    
    def dispatch(self, parsed_command: ParsedCommand) -> Dict:
        if parsed_command.tool == ToolType.UNKNOWN:
            return {
                'success': False,
                'error': f"Outil non reconnu pour: {parsed_command.raw_input}",
                'suggestion': "Format attendu: [outil] : [instruction] : [parametres]"
            }
        
        handler = self.handlers.get(parsed_command.tool)
        if not handler:
            return {
                'success': False,
                'error': f"Handler non disponible pour {parsed_command.tool.value}"
            }
        
        try:
            result = handler.execute(
                instruction=parsed_command.instruction,
                parameters=parsed_command.parameters
            )
            
            if result.get('success') and result.get('raw_output') and not result.get('simulated'):
                try:
                    import sys
                    import os
                    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
                    from ai.claude_api import ClaudeAPI
                    
                    if hasattr(self, '_claude_api_key') and self._claude_api_key:
                        claude = ClaudeAPI(self._claude_api_key)
                        
                        output_for_claude = result.get('raw_output', '')[:300]
                        if result.get('pcap_analysis'):
                            pcap_info = result['pcap_analysis']
                            output_for_claude += f"\n\n=== ANALYSE DETAILLEE DU FICHIER PCAP ===\n"
                            for key, value in pcap_info.items():
                                if key == 'IPs_suspectes' and isinstance(value, dict):
                                    output_for_claude += f"\n{key}:\n"
                                    for ip, info in value.items():
                                        output_for_claude += f"  {ip}: Fournisseur={info.get('Fournisseur', 'Inconnu')}, Ville={info.get('Ville', 'Inconnue')}\n"
                                elif key == 'IPs_DDoS' and isinstance(value, list):
                                    output_for_claude += f"\n{key} (DETECTION DDoS):\n"
                                    for ip_data in value:
                                        output_for_claude += f"  {ip_data.get('ip', 'N/A')}: {ip_data.get('volume', 0)} paquets (TRAFIC ANORMAL)\n"
                                elif key == 'Regles_iptables' and isinstance(value, list):
                                    output_for_claude += f"\n{key} (A APPLIQUER POUR BLOQUER LES IPs DDoS):\n"
                                    for rule in value:
                                        output_for_claude += f"  {rule}\n"
                                elif isinstance(value, str) and len(value) > 0:
                                    cleaned_value = ''.join(char for char in value if ord(char) >= 32 or char in '\n\t')
                                    cleaned_value = cleaned_value[:800]
                                    output_for_claude += f"\n{key}:\n{cleaned_value}\n"
                                elif value:
                                    output_for_claude += f"\n{key}: {value}\n"
                            output_for_claude += "\n=== FIN ANALYSE PCAP ===\n"
                            output_for_claude += "\nIMPORTANT: Analyse en detail les IPs avec trafic anormal, utilise les informations de fournisseur et ville pour expliquer pourquoi ces IPs sont suspectes, detecte les anomalies, et fournis une analyse serieuse de securite.\n"
                            output_for_claude = ''.join(char for char in output_for_claude if ord(char) >= 32 or char in '\n\t')
                        
                        analysis = claude.analyze_results(
                            parsed_command.tool.value,
                            output_for_claude,
                            result.get('command', '')
                        )
                        if analysis and analysis.get('analysis'):
                            result['claude_explanation'] = analysis['analysis']
                except Exception as e:
                    pass
            
            return result
        except Exception as e:
            return {
                'success': False,
                'error': f"Erreur lors de l'execution: {str(e)}"
            }
    
    def set_simulation_mode(self, enabled: bool):
        self.simulation_mode = enabled
        for handler in self.handlers.values():
            if hasattr(handler, 'simulation_mode'):
                handler.simulation_mode = enabled
