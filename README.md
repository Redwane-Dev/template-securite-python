# Securite Python - ESGI M1

## Description

Projet realise dans le cadre du cours de securite Python (M1, ESGI). Il regroupe trois TP independants, chacun dans son propre dossier `src/tpN/` :

- **TP1** : analyse d'un fichier PCAP (detection ARP spoofing, port scan, injection SQL) et generation d'un rapport PDF/JSON/SVG.
- **TP2** : triage de malware.
- **TP3** : "Breach the target" - exploit automatise enchainant une phase web (fuzzing d'endpoints caches, resolution de CAPTCHA par OCR) et une phase reseau (decodage d'un flux chiffre en boucle, sous contrainte de temps) pour recuperer deux drapeaux.

## Installation

Faire un fork puis un clone du projet :

```bash
git clone git@github.com:<VotreNom>/template-securite-python.git
cd template-securite-python
```

Installer les dependances avec Poetry :

```bash
poetry lock
poetry install
```

Le TP3 utilise la reconnaissance optique de caracteres (OCR) pour resoudre les CAPTCHA : en plus des dependances Python (`pytesseract`, `pillow`), le moteur **Tesseract OCR** doit etre installe sur la machine et accessible dans le PATH (binaire `tesseract`).

## Utilisation

TP1 :
```bash
poetry run tp1 --pcap fichier.pcap --out report.json
```

TP3 :
```bash
poetry run tp3 --target http://<ip>:<port>
```

## Tests

```bash
poetry run pytest
```

## Qualite de code

Le projet utilise `ruff` pour le linting et `pre-commit` pour l'executer automatiquement avant chaque commit :

```bash
poetry run ruff check src tests
poetry run pre-commit install
```