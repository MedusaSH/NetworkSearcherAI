#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Moteur d'IA pour la compréhension du langage naturel
Utilise des techniques d'IA pour détecter l'intention et extraire les paramètres
"""

import re
from typing import Dict, List, Tuple, Optional
from collections import Counter
import math


class IntentClassifier:
    """Classifieur d'intention basé sur des embeddings sémantiques et TF-IDF"""
    
    def __init__(self):
        self.tool_embeddings = {
            'nmap': {
                'keywords': ['scan', 'port', 'analyse', 'découvrir', 'détecter', 'service', 'ouvert', 
                            'fermé', 'filtre', 'réseau', 'hôte', 'ip', 'adresse', 'vulnérabilité',
                            'sécurité', 'audit', 'pentest', 'reconnaissance', 'énumération'],
                'actions': ['scanner', 'analyser', 'découvrir', 'tester', 'vérifier', 'examiner'],
                'context': ['réseau', 'système', 'serveur', 'machine', 'hôte']
            },
            'iptables': {
                'keywords': ['bloquer', 'autoriser', 'firewall', 'règle', 'filtre', 'connexion',
                            'entrant', 'sortant', 'trafic', 'paquet', 'refuser', 'accepter',
                            'protéger', 'sécuriser', 'port', 'ip', 'interface'],
                'actions': ['bloquer', 'autoriser', 'refuser', 'accepter', 'filtrer', 'protéger'],
                'context': ['firewall', 'sécurité', 'réseau', 'connexion']
            },
            'dig': {
                'keywords': ['dns', 'résolution', 'domaine', 'enregistrement', 'mx', 'ns', 'a',
                            'aaaa', 'txt', 'cname', 'serveur', 'nom', 'adresse'],
                'actions': ['résoudre', 'interroger', 'vérifier', 'consulter', 'chercher'],
                'context': ['dns', 'domaine', 'nom', 'résolution']
            },
            'whois': {
                'keywords': ['propriétaire', 'domaine', 'registrar', 'enregistrement', 'expiration',
                            'contact', 'organisation', 'as', 'réseau', 'plage', 'ip'],
                'actions': ['consulter', 'vérifier', 'analyser', 'rechercher', 'obtenir'],
                'context': ['domaine', 'ip', 'propriétaire', 'enregistrement']
            },
            'tcpdump': {
                'keywords': ['capture', 'trafic', 'paquet', 'réseau', 'sniff', 'écouter', 'monitor',
                            'analyser', 'protocole', 'interface', 'dns', 'http', 'tcp', 'udp'],
                'actions': ['capturer', 'écouter', 'monitorer', 'analyser', 'sniffer'],
                'context': ['trafic', 'réseau', 'paquet', 'protocole']
            }
        }
        
        self.weights = {
            'keywords': 2.0,
            'actions': 3.0,
            'context': 1.5
        }
    
    def _tokenize(self, text: str) -> List[str]:
        """Tokenise le texte en mots"""
        text = text.lower()
        text = re.sub(r'[^\w\s\.]', ' ', text)
        tokens = text.split()
        return tokens
    
    def _calculate_tf_idf_score(self, tokens: List[str], tool: str) -> float:
        """Calcule un score TF-IDF simplifié pour un outil"""
        tool_data = self.tool_embeddings[tool]
        score = 0.0
        
        token_counts = Counter(tokens)
        total_tokens = len(tokens)
        
        for keyword in tool_data['keywords']:
            if keyword in token_counts:
                tf = token_counts[keyword] / total_tokens if total_tokens > 0 else 0
                score += tf * self.weights['keywords']
        
        for action in tool_data['actions']:
            if action in token_counts:
                tf = token_counts[action] / total_tokens if total_tokens > 0 else 0
                score += tf * self.weights['actions']
        
        for context_word in tool_data['context']:
            if context_word in token_counts:
                tf = token_counts[context_word] / total_tokens if total_tokens > 0 else 0
                score += tf * self.weights['context']
        
        return score
    
    def classify_intent(self, instruction: str) -> Tuple[str, float]:
        """
        Classifie l'intention et retourne l'outil le plus probable avec son score
        
        Returns:
            Tuple (tool_name, confidence_score)
        """
        tokens = self._tokenize(instruction)
        
        if not tokens:
            return ('unknown', 0.0)
        
        scores = {}
        for tool in self.tool_embeddings.keys():
            scores[tool] = self._calculate_tf_idf_score(tokens, tool)
        
        if not scores or max(scores.values()) == 0:
            return ('unknown', 0.0)
        
        best_tool = max(scores, key=scores.get)
        best_score = scores[best_tool]
        
        total_score = sum(scores.values())
        confidence = best_score / total_score if total_score > 0 else 0.0
        
        return (best_tool, confidence)


class EntityExtractor:
    """Extracteur d'entités utilisant des patterns et du NLP"""
    
    def __init__(self):
        self.patterns = {
            'ip': [
                r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
                r'\bip[:\s]+(?:\d{1,3}\.){3}\d{1,3}\b',
                r'\badresse[:\s]+(?:\d{1,3}\.){3}\d{1,3}\b'
            ],
            'domain': [
                r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
                r'\bdomaine[:\s]+(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
            ],
            'port': [
                r'\bport[:\s]*(\d+)\b',
                r'\b(\d+)\s*port\b',
                r'\bport\s+(\d+)\b'
            ],
            'duration': [
                r'(\d+)\s*(?:seconde|secondes|sec|s)\b',
                r'(\d+)\s*(?:minute|minutes|min|m)\b',
                r'(\d+)\s*(?:heure|heures|h)\b'
            ],
            'protocol': [
                r'\b(tcp|udp|icmp|http|https|dns|ssh|ftp|smtp)\b'
            ],
            'interface': [
                r'\b(eth\d+|wlan\d+|lo|any|ens\d+)\b',
                r'\binterface[:\s]+(eth\d+|wlan\d+|lo|any|ens\d+)\b'
            ]
        }
    
    def extract(self, text: str) -> Dict[str, any]:
        """Extrait toutes les entités du texte"""
        entities = {}
        text_lower = text.lower()
        
        for pattern in self.patterns['ip']:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                entities['ip'] = matches[0] if isinstance(matches[0], str) else matches[0]
                if len(matches) > 1:
                    entities['ips'] = matches
                break
        
        for pattern in self.patterns['domain']:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                domain = matches[0] if isinstance(matches[0], str) else matches[0]
                entities['domain'] = domain
                if len(matches) > 1:
                    entities['domains'] = matches
                break
        
        ports = []
        for pattern in self.patterns['port']:
            matches = re.findall(pattern, text_lower, re.IGNORECASE)
            for match in matches:
                port = int(match) if isinstance(match, str) and match.isdigit() else match
                if port not in ports:
                    ports.append(str(port))
        if ports:
            entities['port'] = ports[0]
            if len(ports) > 1:
                entities['ports'] = ports
        
        for pattern in self.patterns['duration']:
            match = re.search(pattern, text_lower)
            if match:
                value = int(match.group(1))
                unit = match.group(2) if len(match.groups()) > 1 else ''
                if 'min' in unit or 'm' in unit:
                    value *= 60
                elif 'h' in unit or 'heure' in unit:
                    value *= 3600
                entities['duration'] = str(value)
                break
        
        for pattern in self.patterns['protocol']:
            match = re.search(pattern, text_lower)
            if match:
                entities['protocol'] = match.group(1).lower()
                break
        
        for pattern in self.patterns['interface']:
            match = re.search(pattern, text_lower)
            if match:
                entities['interface'] = match.group(1) if len(match.groups()) > 0 else match.group(0)
                break
        
        return entities


class AIEngine:
    """Moteur d'IA principal qui combine classification et extraction"""
    
    def __init__(self):
        self.intent_classifier = IntentClassifier()
        self.entity_extractor = EntityExtractor()
    
    def understand(self, user_input: str) -> Dict:
        """
        Comprend la demande de l'utilisateur et retourne une structure analysée
        
        Returns:
            Dict avec 'tool', 'confidence', 'entities', 'instruction'
        """
        tool, confidence = self.intent_classifier.classify_intent(user_input)
        
        entities = self.entity_extractor.extract(user_input)
        
        return {
            'tool': tool,
            'confidence': confidence,
            'entities': entities,
            'instruction': user_input,
            'is_confident': confidence > 0.3  
        }
    
    def suggest_tool(self, instruction: str, explicit_tool: str = "") -> str:
        """
        Suggère l'outil le plus approprié
        
        Args:
            instruction: Instruction de l'utilisateur
            explicit_tool: Outil explicitement mentionné (optionnel)
        
        Returns:
            Nom de l'outil suggéré
        """
        if explicit_tool:
            analysis = self.understand(instruction)
            if analysis['tool'] == explicit_tool.lower() or analysis['confidence'] < 0.4:
                return explicit_tool.lower()
        
        analysis = self.understand(instruction)
        return analysis['tool']
    
    def extract_parameters(self, instruction: str) -> Dict:
        """Extrait les paramètres de l'instruction"""
        return self.entity_extractor.extract(instruction)

