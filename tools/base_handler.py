#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from abc import ABC, abstractmethod
from typing import Dict, List, Optional
import subprocess
import shutil
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.package_manager import PackageManager


class BaseHandler(ABC):
    
    def __init__(self, tool_name: str, simulation_mode: bool = False, auto_install: bool = True):
        self.tool_name = tool_name
        self.simulation_mode = simulation_mode
        self.auto_install = auto_install
        self.tool_path = None
        self.package_manager = PackageManager()
        self._check_availability()
    
    def _check_availability(self) -> bool:
        tool_path = shutil.which(self.tool_name)
        if tool_path:
            self.tool_path = tool_path
            return True
        
        if self.auto_install and not self.simulation_mode:
            print(f"ATTENTION: {self.tool_name} n'est pas installe. Tentative d'installation automatique...")
            success, message = self.package_manager.ensure_installed(self.tool_name, auto_install=True)
            if success:
                tool_path = shutil.which(self.tool_name)
                if tool_path:
                    self.tool_path = tool_path
                    print(f"OK: {message}")
                    return True
                else:
                    print(f"ERREUR: {message}")
                    self.tool_path = self.tool_name
                    return False
            else:
                print(f"ERREUR: {message}")
                self.tool_path = self.tool_name
                return False
        
        self.tool_path = self.tool_name
        return False
    
    def _generate_command(self, instruction: str, parameters: Dict) -> List[str]:
        return self.generate_command(instruction, parameters)
    
    def _simulate_execution(self, command: List[str]) -> Dict:
        return {
            'success': True,
            'output': f"[SIMULATION] Commande generee: {' '.join(command)}\n[SIMULATION] Execution simulee - aucune action reelle effectuee",
            'error': None,
            'returncode': 0,
            'simulated': True
        }
    
    def _run_command(self, command: List[str], requires_sudo: bool = False) -> Dict:
        if self.simulation_mode:
            print(f"[SIMULATION] Commande qui serait executee: {' '.join(command)}", flush=True)
            return self._simulate_execution(command)
        
        if requires_sudo:
            command = ['sudo'] + command
        
        try:
            command = [str(arg) for arg in command]
            
            if command and command[0] == self.tool_name and self.tool_path:
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
                capture_output=True,
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
                'returncode': result.returncode,
                'simulated': False
            }
        except FileNotFoundError as e:
            return {
                'success': False,
                'output': '',
                'error': f"{self.tool_name} n'est pas installe: {str(e)}",
                'returncode': -1,
                'simulated': False
            }
        except OSError as e:
            return {
                'success': False,
                'output': '',
                'error': f"Erreur systeme: {str(e)}",
                'returncode': -1,
                'simulated': False
            }
        except Exception as e:
            return {
                'success': False,
                'output': '',
                'error': f"Erreur: {str(e)}",
                'returncode': -1,
                'simulated': False
            }
    
    @abstractmethod
    def generate_command(self, instruction: str, parameters: Dict) -> List[str]:
        pass
    
    @abstractmethod
    def execute(self, instruction: str, parameters: Dict) -> Dict:
        pass
    
    @abstractmethod
    def analyze_results(self, output: str, parameters: Dict) -> Dict:
        pass
