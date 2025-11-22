#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Classe de base pour tous les outils de cybersécurité
"""

from abc import ABC, abstractmethod
from typing import Dict, Optional
import subprocess
import shutil


class BaseTool(ABC):
    """Classe abstraite de base pour tous les outils"""
    
    def __init__(self, tool_name: str):
        self.tool_name = tool_name
        self.tool_path = tool_name  
        self._check_availability()
    
    def _check_availability(self) -> bool:
        """Vérifie si l'outil est disponible sur le système"""

        tool_path = shutil.which(self.tool_name)
        if tool_path:
            self.tool_path = tool_path
        else:
            self.tool_path = self.tool_name  
        return tool_path is not None
    
    def _run_command(self, command: list, requires_sudo: bool = False, capture_output: bool = True) -> Dict:
        """
        Exécute une commande système
        
        Args:
            command: Liste des arguments de la commande
            requires_sudo: Si True, préfixe avec sudo
            capture_output: Si True, capture la sortie
        
        Returns:
            Dict avec 'success', 'output', 'error'
        """
        if requires_sudo:
            command = ['sudo'] + command
        
        try:
            if not isinstance(command, list):
                command = [str(command)]
            
            command = [str(arg) for arg in command]
            
            if command and command[0] == self.tool_name and hasattr(self, 'tool_path') and self.tool_path:
                command[0] = self.tool_path
            
            if not command:
                return {
                    'success': False,
                    'output': '',
                    'error': 'Commande vide',
                    'returncode': -1
                }
            
            result = subprocess.run(
                command,
                capture_output=capture_output,
                text=True,
                timeout=300,  
                check=False,
                stdin=subprocess.DEVNULL,  
                shell=False  
            )
            
            combined_output = result.stdout or ""
            if result.stderr:
                if combined_output:
                    combined_output += "\n" + result.stderr
                else:
                    combined_output = result.stderr
            
            error_msg = None
            if result.returncode != 0:
                error_msg = result.stderr or combined_output or "Erreur inconnue"
            
            return {
                'success': result.returncode == 0,
                'output': combined_output,
                'error': error_msg,
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'output': '',
                'error': 'Commande expirée (timeout > 5 minutes)',
                'returncode': -1
            }
        except FileNotFoundError as e:
            return {
                'success': False,
                'output': '',
                'error': f"{self.tool_name} n'est pas installé ou n'est pas dans le PATH: {str(e)}",
                'returncode': -1
            }
        except OSError as e:
            return {
                'success': False,
                'output': '',
                'error': f"Erreur système lors de l'exécution de {self.tool_name}: {str(e)}. Commande: {' '.join(command)}",
                'returncode': -1
            }
        except Exception as e:
            return {
                'success': False,
                'output': '',
                'error': f"Erreur lors de l'exécution: {str(e)}. Commande: {' '.join(command) if 'command' in locals() else 'N/A'}",
                'returncode': -1
            }
    
    @abstractmethod
    def execute(self, instruction: str, parameters: Dict) -> Dict:
        """
        Exécute l'instruction avec les paramètres donnés
        
        Args:
            instruction: Instruction en langage naturel
            parameters: Dictionnaire de paramètres extraits
        
        Returns:
            Dict avec les résultats formatés
        """
        pass
    
    @abstractmethod
    def generate_command(self, instruction: str, parameters: Dict) -> list:
        """
        Génère la commande CLI à partir de l'instruction
        
        Args:
            instruction: Instruction en langage naturel
            parameters: Dictionnaire de paramètres
        
        Returns:
            Liste des arguments de la commande
        """
        pass

