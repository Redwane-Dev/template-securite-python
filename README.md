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

## TP2 - Triage automatisé de malware

L'outil analyse chaque fichier d'un dossier sans jamais l'exécuter : empreintes (SHA-256, MD5),
entropie, type de fichier (python-magic), IOC (domaines, IP, URLs, mutex, clés de registre, chemins),
structure PE/ELF avec lief, règles YARA, recherche du flag `ESGI{...}`, puis verdict d'un LLM.

```bash
poetry run tp2 --samples DOSSIER --rules DOSSIER --out DOSSIER
```

- `--samples` : échantillons à analyser ;
- `--rules` : règles YARA fournies (fichiers `.yar` / `.yara`), nos règles sont ajoutées automatiquement ;
- `--out` : un fichier `<sha256>.json` par échantillon et le rapport `triage_report.pdf` ;
- `--no-llm` : verdict uniquement par les règles.

### LLM

Le backend est choisi à partir du fichier `.env` à la racine :

```
OPENROUTER_API_KEY=sk-or-...   # OpenRouter (utilisé pour la correction)
MISTRAL_API_KEY=...            # Mistral (développement)
LLM_BACKEND=ollama             # optionnel : forcer openrouter / mistral / ollama / offline
```

Sans clé ou sans réseau, l'outil passe en mode hors ligne : le verdict est calculé par les règles.

### Sécurité de la chaîne LLM

- seul un résumé structuré (JSON des indicateurs) est envoyé, jamais le binaire ;
- les données extraites sont placées entre des balises `<<<DEBUT_DONNEES_NON_FIABLES>>>` /
  `<<<FIN_DONNEES_NON_FIABLES>>>` et le prompt système interdit de suivre leurs instructions ;
- les chaînes qui ressemblent à une injection de prompt sont détectées et retirées des IOC et du flag ;
- la réponse est validée (JSON strict, champs obligatoires, score borné entre 0 et 10, identifiants MITRE) ;
- le LLM ne décide pas seul : la famille et le score des règles (YARA, IOC, API) servent de plancher.

### Règles YARA personnelles

Elles sont dans `src/tp2/utils/scanner.py` (`CUSTOM_RULES`) : `Prompt_Injection_Attempt`,
`Registry_Run_Persistence`, `C2_Gate_Url` et `Packed_High_Entropy`.

### Tests

```bash
poetry run pytest tests/tp2
```
