#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re
from typing import Dict, Optional, List

try:
    from anthropic import Anthropic
    ANTHROPIC_SDK_AVAILABLE = True
except ImportError:
    ANTHROPIC_SDK_AVAILABLE = False
    import requests


class ClaudeAPI:
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.model = "claude-3-haiku-20240307"
        
        if ANTHROPIC_SDK_AVAILABLE:
            self.client = Anthropic(api_key=api_key)
        else:
            self.base_url = "https://api.anthropic.com/v1/messages"
    
    def _make_request(self, messages: List[Dict], system: str = None, max_tokens: int = 1024) -> Dict:
        if ANTHROPIC_SDK_AVAILABLE:
            models_to_try = [
                "claude-3-haiku-20240307",
                "claude-3-sonnet-20240229",
                "claude-3-opus-20240229",
                "claude-3-5-haiku-20241022",
                "claude-3-5-sonnet-20241022",
            ]
            
            for model in models_to_try:
                try:
                    response = self.client.messages.create(
                        model=model,
                        max_tokens=max_tokens,
                        messages=messages,
                        system=system if system else None
                    )
                    self.model = model
                    return {
                        "content": [{"text": response.content[0].text}]
                    }
                except Exception as e:
                    error_str = str(e)
                    if "404" not in error_str and "not_found" not in error_str.lower():
                        print(f"Erreur SDK Anthropic avec {model}: {str(e)}", flush=True)
                        return {"error": str(e)}
                    continue
            
            print(f"Erreur: Aucun modele Claude disponible. Tous les modeles ont retourne 404.", flush=True)
            return {"error": "Aucun modele Claude disponible"}
        else:
            headers = {
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json"
            }
            
            payload = {
                "model": self.model,
                "max_tokens": max_tokens,
                "messages": messages
            }
            
            if system:
                payload["system"] = system
            
            try:
                response = requests.post(self.base_url, headers=headers, json=payload, timeout=30)
                response.raise_for_status()
                return response.json()
            except requests.exceptions.HTTPError as e:
                error_detail = f"HTTP {response.status_code}: {response.text[:200]}"
                print(f"Erreur HTTP Claude: {error_detail}", flush=True)
                return {"error": error_detail}
            except requests.exceptions.RequestException as e:
                print(f"Erreur requete Claude: {str(e)}", flush=True)
                return {"error": str(e)}
            except Exception as e:
                print(f"Erreur inattendue Claude: {str(e)}", flush=True)
                return {"error": str(e)}
    
    def understand_command(self, user_input: str) -> Dict:
        system_prompt = """Tu es un assistant expert en cybersecurite qui aide a interpreter des commandes pour des outils de securite.

Outils disponibles:
- nmap: scan de ports, analyse de services, detection OS, scanner une IP, analyser un serveur
- iptables: configuration firewall, regles de filtrage, bloquer une IP, autoriser un port
- tshark: capture de trafic reseau, capturer des paquets, analyser le trafic, wireshark, pcap

Mots-cles pour detection automatique:
- nmap: "scan", "scanner", "port", "service", "analyse IP", "detecter OS", "nmap"
- iptables: "bloque", "autorise", "firewall", "regle", "filtre", "iptables"
- tshark: "capture", "paquet", "trafic", "reseau", "tshark", "tcpdump", "wireshark", "pcap", "analyser le trafic"

Pour chaque commande, identifie AUTOMATIQUEMENT l'outil le plus approprie meme si l'utilisateur ne le mentionne pas explicitement.

Exemples:
- "capture les paquets pendant 10 secondes" -> tshark
- "scan cette IP 192.168.1.1" -> nmap
- "bloque cette IP 1.2.3.4" -> iptables
- "analyse le trafic reseau" -> tshark

Pour chaque commande, identifie:
1. L'outil a utiliser (tool) - DETECTION AUTOMATIQUE OBLIGATOIRE
2. Les parametres (ip, domain, port, protocol, duration, interface, scan_type, etc.)
3. Le type d'action demandee

Pour nmap, detecte le type de scan demande:
- scan_type: "os" si l'utilisateur demande juste l'OS (ex: "juste l'os", "uniquement l'os")
- scan_type: "version" si l'utilisateur demande juste les versions de services
- scan_type: "ports" si l'utilisateur demande juste les ports ouverts
- scan_type: "full" si l'utilisateur demande un scan complet
- scan_type: "quick" si l'utilisateur demande un scan rapide
- scan_type: "stealth" si l'utilisateur demande un scan furtif

Reponds UNIQUEMENT en JSON valide avec cette structure:
{
    "tool": "nmap|iptables|tshark",
    "confidence": 0.0-1.0,
    "parameters": {
        "ip": "...",
        "domain": "...",
        "port": "...",
        "protocol": "...",
        "duration": "...",
        "interface": "...",
        "scan_type": "os|version|ports|full|quick|stealth"
    },
    "instruction_parsed": "description de ce qui doit etre fait"
}"""

        messages = [
            {
                "role": "user",
                "content": f"Analyse cette commande de cybersecurite et identifie AUTOMATIQUEMENT l'outil le plus approprie (nmap, iptables, ou tshark) ainsi que les parametres:\n\n{user_input}\n\nIMPORTANT: Detecte l'outil meme si l'utilisateur ne le mentionne pas explicitement. Utilise les mots-cles et le contexte pour choisir le bon outil."
            }
        ]
        
        response = self._make_request(messages, system=system_prompt, max_tokens=500)
        
        if "error" in response:
            return {"error": response["error"], "tool": "unknown"}
        
        try:
            content = response.get("content", [])
            if content and len(content) > 0:
                text = content[0].get("text", "")
                json_start = text.find("{")
                json_end = text.rfind("}") + 1
                if json_start >= 0 and json_end > json_start:
                    json_str = text[json_start:json_end]
                    parsed = json.loads(json_str)
                    return parsed
        except (json.JSONDecodeError, KeyError, IndexError) as e:
            pass
        
        return {"error": "Impossible de parser la reponse de Claude", "tool": "unknown"}
    
    def analyze_results(self, tool: str, output: str, command: str) -> Dict:
        system_prompt = """Tu es un expert en cybersecurite qui analyse les resultats d'outils de securite.

Analyse les resultats et fournis une explication detaillee et serieuse de ce qui a ete fait avec la commande.

Si l'outil est tshark et qu'il y a une analyse de fichier pcap, tu DOIS analyser EN DETAIL:
- Les protocoles detectes dans le fichier et leur repartition
- Les statistiques generales (nombre de paquets, taille totale, duree de capture)
- Les conversations IP principales (top talkers) avec les volumes de trafic
- Les endpoints IP qui generent le plus de trafic
- DETECTION D'ANOMALIES: Identifie les IPs avec un trafic anormalement eleve ou suspect
- Analyse du trafic HTTP si present (requetes, reponses, codes d'erreur)
- Analyse des requetes DNS si present (domaines interroges, reponses)
- Signes potentiels d'activite malveillante ou de trafic suspect
- Recommandations de securite basees sur l'analyse

Pour chaque IP avec trafic anormal, explique:
- Pourquoi c'est anormal (volume, frequence, type de trafic)
- Quels sont les risques potentiels
- Ce qu'il faudrait investiguer

Explique aussi chaque argument de la commande pour que l'utilisateur apprenne.

Reponds UNIQUEMENT en JSON valide:
{
    "analysis": "explication TRES DETAILLEE et SERIEUSE de ce qui a ete fait avec la commande, incluant une analyse approfondie du fichier pcap avec detection d'anomalies et analyse des IPs suspectes",
    "risks": ["risque 1", "risque 2", ...],
    "recommendations": ["recommandation 1", "recommandation 2", ...]
}"""

        cleaned_output = ''.join(char for char in output[:2000] if ord(char) >= 32 or char in '\n\t')
        
        content = f"Commande executee: {command}\n\nOutil: {tool}\n\nResultats de la commande:\n{cleaned_output}\n\n"
        
        if "pcap" in output.lower() or "capture" in output.lower() or tool == "tshark":
            content += "\nIMPORTANT: Analyse le fichier pcap capture et fournis:\n"
            content += "- Les protocoles detectes dans le fichier\n"
            content += "- Les statistiques generales (nombre de paquets, taille, etc.)\n"
            content += "- Les conversations IP principales (top talkers)\n"
            if "IPs_suspectes" in output:
                content += "- ANALYSE EN DETAIL des IPs suspectes avec trafic anormal: utilise les informations de fournisseur et ville pour expliquer pourquoi ces IPs sont suspectes\n"
            if "IPs_DDoS" in output or "Regles_iptables" in output:
                content += "- DETECTION DDoS: Analyse en detail les IPs detectees comme faisant un DDoS, explique pourquoi c'est un DDoS, et mentionne les regles iptables generees pour les bloquer\n"
            content += "- Toute information interessante sur le trafic capture\n\n"
        
        content += "Explique en 3-5 lignes ce qui a ete fait avec cette commande, ce que chaque partie de la commande signifie, et ce que les resultats signifient. Inclus la commande dans ton explication pour que l'utilisateur apprenne."
        
        messages = [
            {
                "role": "user",
                "content": content
            }
        ]
        
        response = self._make_request(messages, system=system_prompt, max_tokens=1000)
        
        if "error" in response:
            error_msg = response.get("error", "Erreur inconnue")
            print(f"Erreur API Claude: {error_msg}", flush=True)
            return {
                "analysis": f"Erreur lors de l'analyse par Claude: {error_msg[:100]}",
                "risks": [],
                "recommendations": []
            }
        
        try:
            content = response.get("content", [])
            if content and len(content) > 0:
                text = content[0].get("text", "")
                if not text:
                    print("Reponse Claude vide", flush=True)
                    return {
                        "analysis": "Aucune reponse de Claude",
                        "risks": [],
                        "recommendations": []
                    }
                json_start = text.find("{")
                json_end = text.rfind("}") + 1
                if json_start >= 0 and json_end > json_start:
                    json_str = text[json_start:json_end]
                    cleaned_json = json_str.encode('utf-8', errors='ignore').decode('utf-8')
                    cleaned_json = ''.join(char for char in cleaned_json if ord(char) >= 32 or char in '\n\t\r')
                    cleaned_json = cleaned_json.replace('\x00', '').replace('\x1f', '')
                    try:
                        parsed = json.loads(cleaned_json)
                        return parsed
                    except json.JSONDecodeError:
                        analysis_text = text[json_start:json_start+800] if len(text) > json_start+800 else text[json_start:]
                        analysis_text = ''.join(char for char in analysis_text if ord(char) >= 32 or char in '\n\t')
                        if '"analysis"' in cleaned_json.lower():
                            analysis_match = re.search(r'"analysis"\s*:\s*"([^"]*)"', cleaned_json, re.DOTALL)
                            if analysis_match:
                                return {
                                    "analysis": analysis_match.group(1)[:1000],
                                    "risks": [],
                                    "recommendations": []
                                }
                        return {
                            "analysis": analysis_text[:1000] if analysis_text else "Reponse Claude non parseable",
                            "risks": [],
                            "recommendations": []
                        }
                else:
                    cleaned_text = ''.join(char for char in text[:1000] if ord(char) >= 32 or char in '\n\t')
                    return {
                        "analysis": cleaned_text if cleaned_text else "Reponse Claude non parseable",
                        "risks": [],
                        "recommendations": []
                    }
            else:
                print(f"Format de reponse Claude inattendu: {response}", flush=True)
        except json.JSONDecodeError as e:
            print(f"Erreur JSON Claude: {e}", flush=True)
        except (KeyError, IndexError) as e:
            print(f"Erreur structure reponse Claude: {e}", flush=True)
        
        return {
            "analysis": "Analyse effectuee (format non standard)",
            "risks": [],
            "recommendations": []
        }
