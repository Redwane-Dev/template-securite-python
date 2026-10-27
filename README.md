# Template code Sécurité Python

## Description

Projet contenant les modèles de TP pour le cours de sécurité Python de 4e année de l'ESGI.

## Installation

Faire un fork puis un clone du projet :

```bash
git clone git@github.com:<VotreNom>/template-securite-python.git
```

Installer les dépendances :

```bash
cd template-securite-python
poetry lock
poetry install
```

## Utilisation

Lancer le projet :

```bash
poetry run tp1
```

### TP1 - IDS/IPS maison

Analyse d'un fichier PCAP (mode utilisé pour la correction) :

```bash
poetry run tp1 --pcap capture.pcap --out report.json
```

Capture en direct (Npcap requis sous Windows, droits administrateur) :

```bash
poetry run tp1 --iface eth0 --count 500 --timeout 60 --out report.json
```

Sans `--pcap` ni `--iface`, la liste des interfaces est affichée pour en choisir une.

Fichiers produits :

- `report.json` : protocoles, attaques (`arp_spoofing`, `port_scan`, `sql_injection`) et flag ;
- `report.pdf` (ou `--pdf FICHIER`) : tableau, graphique, analyse du trafic et règles de blocage proposées ;
- `report_graph.svg` : graphique pygal.

Lancer les tests :

```bash
poetry run pytest tests/tp1
```
