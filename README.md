# PcapSleuth - Outil d’Analyse Forensique Réseau (DFIR)

## Présentation du projet
PcapSleuth est un outil développé en Python pour l’analyse forensique des fichiers PCAP.  
Il permet de détecter des activités suspectes comme le port scanning, d’extraire les informations réseau et de générer des rapports automatiques.

---

## Objectifs
- Analyse automatique des fichiers PCAP
- Extraction des IP, ports, protocoles et hostnames
- Détection des attaques de type port scanning
- Génération de rapports et visualisations
- Support du processus DFIR (Digital Forensics & Incident Response)

---

## Technologies utilisées
- Python 3
- Scapy
- Pandas
- Matplotlib
- Wireshark
- Kali Linux
- Ubuntu
- Nmap

---
 
## Structure du projet

```bash
PcapSleuth-Project/
│
├── data/                 # Fichiers PCAP et résultats
├── src/                  # Code source
│   └── parser.py
├── venv/                 # Environnement virtuel
├── requirements.txt
└── README.md
