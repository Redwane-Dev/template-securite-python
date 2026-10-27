# Règles YARA

Placer ici les règles YARA fournies (`.yar`, `.yara`), puis lancer :

```bash
poetry run tp2 --samples DOSSIER --rules rules --out out
```

Nos propres règles sont écrites directement dans `src/tp2/utils/scanner.py` (`CUSTOM_RULES`)
car l'archive déposée ne conserve pas les fichiers `.yar`.
