#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import sys
import os
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from ai.claude_api import ClaudeAPI
    CLAUDE_AVAILABLE = True
except ImportError:
    CLAUDE_AVAILABLE = False
    try:
        from ai_engine import AIEngine
    except ImportError:
        AIEngine = None


class ToolType(Enum):
    NMAP = "nmap"
    IPTABLES = "iptables"
    TSHARK = "tshark"
    UNKNOWN = "unknown"


@dataclass
class ParsedCommand:
    tool: ToolType
    instruction: str
    parameters: Dict[str, str]
    raw_input: str
    confidence: float = 0.0


class CommandParser:
    
    def __init__(self, claude_api_key: str = None):
        self.use_claude = CLAUDE_AVAILABLE and claude_api_key is not None
        
        if self.use_claude:
            self.claude_api = ClaudeAPI(claude_api_key)
        elif AIEngine:
            self.ai_engine = AIEngine()
        else:
            self.ai_engine = None
        
        self.tool_name_map = {
            'nmap': ToolType.NMAP,
            'iptables': ToolType.IPTABLES,
            'tshark': ToolType.TSHARK,
            'tcpdump': ToolType.TSHARK,
        }
    
    def parse(self, user_input: str) -> ParsedCommand:
        if self.use_claude:
            return self._parse_with_claude(user_input)
        
        pattern = r'^([^:]+?)\s*:\s*(.+?)(?:\s*:\s*(.+))?$'
        match = re.match(pattern, user_input.strip(), re.IGNORECASE)
        
        if match:
            tool_name = match.group(1).strip().lower()
            instruction = match.group(2).strip()
            params_str = match.group(3).strip() if match.group(3) else ""
            
            tool, confidence = self._identify_tool(tool_name, instruction)
            parameters = self._extract_parameters(params_str, instruction)
            
            return ParsedCommand(
                tool=tool,
                instruction=instruction,
                parameters=parameters,
                raw_input=user_input,
                confidence=confidence
            )
        else:
            tool, confidence = self._identify_tool("", user_input)
            parameters = self._extract_parameters("", user_input)
            
            return ParsedCommand(
                tool=tool,
                instruction=user_input,
                parameters=parameters,
                raw_input=user_input,
                confidence=confidence
            )
    
    def _parse_with_claude(self, user_input: str) -> ParsedCommand:
        result = self.claude_api.understand_command(user_input)
        
        if "error" in result:
            if hasattr(self, 'ai_engine') and self.ai_engine:
                tool, confidence = self._identify_tool("", user_input)
                parameters = self._extract_parameters("", user_input)
                return ParsedCommand(
                    tool=tool,
                    instruction=user_input,
                    parameters=parameters,
                    raw_input=user_input,
                    confidence=0.5
                )
            else:
                tool, confidence = self._identify_tool("", user_input)
                parameters = self._extract_parameters("", user_input)
                return ParsedCommand(
                    tool=tool,
                    instruction=user_input,
                    parameters=parameters,
                    raw_input=user_input,
                    confidence=0.5
                )
        
        tool_name = result.get("tool", "unknown").lower()
        tool = self.tool_name_map.get(tool_name, ToolType.UNKNOWN)
        confidence = result.get("confidence", 0.8)
        parameters = result.get("parameters", {})
        instruction = result.get("instruction_parsed", user_input)
        
        return ParsedCommand(
            tool=tool,
            instruction=instruction,
            parameters=parameters,
            raw_input=user_input,
            confidence=confidence
        )
    
    def _identify_tool(self, explicit_tool: str, instruction: str) -> Tuple[ToolType, float]:
        if explicit_tool:
            tool_name = explicit_tool.lower().strip()
            if tool_name in self.tool_name_map:
                return (self.tool_name_map[tool_name], 1.0)
        
        if not hasattr(self, 'ai_engine') or self.ai_engine is None:
            instruction_lower = instruction.lower()
            
            nmap_keywords = ['scan', 'scanner', 'port', 'service', 'analyse ip', 'detecter os', 'nmap', 'scanne']
            iptables_keywords = ['bloque', 'autorise', 'firewall', 'regle', 'filtre', 'iptables', 'bloquer', 'autoriser']
            tshark_keywords = ['capture', 'paquet', 'trafic', 'reseau', 'tshark', 'tcpdump', 'wireshark', 'pcap', 'analyser le trafic', 'capturer']
            
            nmap_score = sum(1 for keyword in nmap_keywords if keyword in instruction_lower)
            iptables_score = sum(1 for keyword in iptables_keywords if keyword in instruction_lower)
            tshark_score = sum(1 for keyword in tshark_keywords if keyword in instruction_lower)
            
            if tshark_score > 0 and tshark_score >= max(nmap_score, iptables_score):
                return (ToolType.TSHARK, min(0.7 + (tshark_score * 0.1), 0.95))
            elif nmap_score > 0 and nmap_score >= iptables_score:
                return (ToolType.NMAP, min(0.7 + (nmap_score * 0.1), 0.95))
            elif iptables_score > 0:
                return (ToolType.IPTABLES, min(0.7 + (iptables_score * 0.1), 0.95))
            
            return (ToolType.UNKNOWN, 0.0)
        
        try:
            suggested_tool = self.ai_engine.suggest_tool(instruction, explicit_tool)
            analysis = self.ai_engine.understand(instruction)
            confidence = analysis.get('confidence', 0.0)
            
            if suggested_tool in self.tool_name_map:
                return (self.tool_name_map[suggested_tool], confidence)
        except:
            pass
        
        return (ToolType.UNKNOWN, 0.0)
    
    def _extract_parameters(self, params_str: str, instruction: str) -> Dict[str, str]:
        full_text = params_str + " " + instruction if params_str else instruction
        full_text_lower = full_text.lower()
        
        if not hasattr(self, 'ai_engine') or self.ai_engine is None:
            parameters = {}
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
            port_pattern = r'\bport[:\s]*(\d+)\b|\b(\d+)\s*port\b'
            
            ips = re.findall(ip_pattern, full_text)
            if ips:
                parameters['ip'] = ips[0]
            
            domains = re.findall(domain_pattern, full_text)
            if domains:
                parameters['domain'] = domains[0]
            
            ports = re.findall(port_pattern, full_text, re.IGNORECASE)
            if ports:
                port_list = [p[0] or p[1] for p in ports if p[0] or p[1]]
                if port_list:
                    parameters['port'] = port_list[0]
            
            duration_pattern = r'(\d+)\s*(?:seconde|secondes|sec|s|second)'
            duration_match = re.search(duration_pattern, full_text, re.IGNORECASE)
            if duration_match:
                parameters['duration'] = duration_match.group(1)
            
            if 'juste l\'os' in full_text_lower or 'uniquement l\'os' in full_text_lower or 'seulement l\'os' in full_text_lower or ('os' in full_text_lower and ('juste' in full_text_lower or 'uniquement' in full_text_lower or 'seulement' in full_text_lower)):
                parameters['scan_type'] = 'os'
            elif 'juste la version' in full_text_lower or 'uniquement la version' in full_text_lower or ('version' in full_text_lower and ('juste' in full_text_lower or 'uniquement' in full_text_lower)):
                parameters['scan_type'] = 'version'
            elif 'juste les ports' in full_text_lower or 'uniquement les ports' in full_text_lower:
                parameters['scan_type'] = 'ports'
            elif 'tout' in full_text_lower or 'complet' in full_text_lower or 'utile' in full_text_lower:
                parameters['scan_type'] = 'full'
            elif 'rapide' in full_text_lower or 'quick' in full_text_lower:
                parameters['scan_type'] = 'quick'
            elif 'stealth' in full_text_lower or 'furtif' in full_text_lower:
                parameters['scan_type'] = 'stealth'
            
            return parameters
        
        try:
            return self.ai_engine.extract_parameters(full_text)
        except:
            return {}
