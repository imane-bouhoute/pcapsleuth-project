# PcapSleuth - Outil d’Analyse Forensique Réseau (DFIR)

## Présentation du projet

PcapSleuth est un outil développé en Python pour l’analyse forensique des fichiers PCAP. Il permet de détecter des activités suspectes comme le port scanning, d’extraire des informations réseau importantes et de générer des rapports d’analyse dans un contexte DFIR (Digital Forensics and Incident Response).

---

## Objectifs

- Analyse automatique des fichiers PCAP
- Extraction des adresses IP, ports, protocoles et hostnames
- Détection des attaques de type port scanning
- Génération de rapports et visualisations
- Support du processus DFIR

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
├── data/
│   ├── scan.pcapng
│   ├── attack.pcapng
│   ├── analysis_results.csv
│   └── traffic_chart.png
│
├── src/
│   └── parser.py
│
├── requirements.txt
├── README.md
└── .gitignore
