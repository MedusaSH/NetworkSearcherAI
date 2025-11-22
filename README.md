# 🔒 Orchestrateur d'Outils de Cybersécurité avec IA

Un système d'intelligence artificielle qui interprète les demandes en langage naturel et orchestre automatiquement les outils de cybersécurité (nmap, iptables, dig, whois, tcpdump).

## 🤖 Intelligence Artificielle

Ce système utilise de **vraies techniques d'IA** :

- **Classification d'intention** : Utilise TF-IDF et embeddings sémantiques pour comprendre l'intention de l'utilisateur
- **Extraction d'entités (NLP)** : Identifie automatiquement les IPs, domaines, ports, protocoles, etc.
- **Scoring de confiance** : Évalue la probabilité que l'outil détecté soit le bon
- **Compréhension contextuelle** : Analyse le contexte sémantique des mots-clés, actions et concepts

## 🎯 Fonctionnalités

- **Interprétation naturelle avec IA** : Comprend les instructions en français grâce au NLP
- **Détection automatique intelligente** : Identifie l'outil approprié même si non explicitement mentionné
- **Génération de commandes** : Crée les commandes CLI exactes et optimisées
- **Exécution sécurisée** : Exécute les commandes avec gestion d'erreurs
- **Analyse intelligente** : Interprète les résultats et fournit des recommandations

## 📦 Installation

### Prérequis

Les outils suivants doivent être installés sur votre système :

- **nmap** : `sudo apt-get install nmap` (Linux) ou `brew install nmap` (macOS)
- **iptables** : Généralement pré-installé sur Linux
- **dig** : `sudo apt-get install dnsutils` (Linux) ou `brew install bind` (macOS)
- **whois** : `sudo apt-get install whois` (Linux) ou `brew install whois` (macOS)
- **tcpdump** : `sudo apt-get install tcpdump` (Linux) ou `brew install tcpdump` (macOS)

### Installation Python

```bash
# Cloner ou télécharger le projet
cd AI

# Python 3.7+ requis (vérifier avec python3 --version)
# Aucune dépendance externe requise (utilise uniquement la bibliothèque standard)
```

## 🚀 Utilisation

### Mode interactif

```bash
python3 orchestrator.py
```

Puis entrez vos commandes au format :
```
[outil] : [instruction] : [paramètres]
```

### Mode ligne de commande

```bash
python3 orchestrator.py "nmap : je veux analyser tout ce qu'il y a d'utile dans cette IP : 192.168.1.20"
```

## 📝 Exemples d'utilisation

### Nmap - Scan complet d'une IP

```
nmap : je veux analyser tout ce qu'il y a d'utile dans cette IP : 192.168.1.20
```

**Commande générée :**
```bash
nmap -A -sV -O -Pn 192.168.1.20
```

### Iptables - Bloquer les connexions entrantes sauf SSH

```
iptables : bloque toutes les connexions entrantes sauf via SSH
```

**Commande générée :**
```bash
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -j DROP
```

### Whois - Analyser un domaine

```
whois : analyse ce domaine : example.com
```

**Commande générée :**
```bash
whois example.com
```

### Dig - Requête DNS

```
dig : résolution DNS pour google.com
```

**Commande générée :**
```bash
dig A google.com +noall +answer
```

### Tcpdump - Capture DNS

```
tcpdump : capture le trafic dns sur 10 secondes
```

**Commande générée :**
```bash
sudo tcpdump -i any udp port 53 -n -v -G 10 -W 1
```

## 📌 Format de réponse

Chaque exécution génère un rapport en 3 parties :

### 1. Commande générée
La commande exacte qui sera/serait exécutée

### 2. Résultat
- Résumé lisible
- Détails importants (ports, services, etc.)
- Sortie brute de l'outil

### 3. Analyse synthétique
- Interprétation technique
- Risques identifiés
- Recommandations de sécurité

## 🛠️ Outils supportés

| Outil | Description | Détection automatique |
|-------|-------------|----------------------|
| **nmap** | Scan de ports et services | ✅ |
| **iptables** | Configuration firewall | ✅ |
| **dig** | Requêtes DNS | ✅ |
| **whois** | Informations domaine/IP | ✅ |
| **tcpdump** | Capture de trafic réseau | ✅ |

## ⚠️ Sécurité et légalité

- **Privilèges** : Certaines commandes nécessitent `sudo` (notamment iptables et tcpdump)
- **Autorisation** : Assurez-vous d'avoir l'autorisation légale avant d'analyser des systèmes tiers
- **Test uniquement** : Utilisez uniquement sur vos propres systèmes ou avec autorisation explicite
- **Pas de destruction** : Le système ne génère jamais de commandes destructives

## 🔧 Architecture

```
orchestrator.py          # Point d'entrée principal
├── ai_engine.py         # 🤖 Moteur d'IA (classification + extraction)
│   ├── IntentClassifier # Classification d'intention avec TF-IDF
│   ├── EntityExtractor  # Extraction d'entités (NLP)
│   └── AIEngine         # Orchestrateur IA
├── tools/
│   ├── __init__.py
│   ├── base_tool.py     # Classe de base abstraite
│   ├── nmap_tool.py     # Module nmap
│   ├── iptables_tool.py # Module iptables
│   ├── dig_tool.py      # Module dig
│   ├── whois_tool.py    # Module whois
│   └── tcpdump_tool.py  # Module tcpdump
```

## 🧠 Comment l'IA fonctionne

### Classification d'intention
Le système utilise des **embeddings sémantiques** et **TF-IDF** pour classer l'intention :
- Analyse les mots-clés, actions et contexte
- Calcule un score de confiance pour chaque outil
- Choisit l'outil avec le score le plus élevé

### Extraction d'entités
Utilise du **NLP (Natural Language Processing)** pour extraire :
- Adresses IP
- Domaines
- Ports
- Protocoles (TCP, UDP, DNS, HTTP, etc.)
- Durées
- Interfaces réseau

### Exemple de fonctionnement IA

```
Input: "Je veux scanner tous les ports ouverts de cette machine 192.168.1.20"

IA analyse:
- Mots-clés: "scanner", "ports", "ouverts" → score nmap: 0.85
- Action: "scanner" → score nmap: 0.90
- Contexte: "machine", "réseau" → score nmap: 0.80
- Entité extraite: IP = 192.168.1.20

Résultat: nmap avec confiance 0.87
```

## 📚 Extensibilité

Pour ajouter un nouvel outil :

1. Créer un nouveau fichier dans `tools/` (ex: `tools/newtool_tool.py`)
2. Hériter de `BaseTool`
3. Implémenter `generate_command()` et `execute()`
4. Ajouter l'outil dans `orchestrator.py` (dictionnaire `self.tools` et patterns)

## 🐛 Dépannage

**Erreur "outil non trouvé"** :
- Vérifiez que l'outil est installé : `which nmap`
- Vérifiez qu'il est dans le PATH

**Erreur de permissions** :
- Certaines commandes nécessitent sudo
- Le système vous avertira si c'est le cas

**Commande non reconnue** :
- Utilisez le format : `[outil] : [instruction] : [paramètres]`
- Ou laissez le système détecter automatiquement l'outil

## 📄 Licence

Ce projet est fourni à des fins éducatives et de test. Utilisez de manière responsable et légale.

## 🤝 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à :
- Ajouter de nouveaux outils
- Améliorer la détection automatique
- Enrichir l'analyse des résultats

