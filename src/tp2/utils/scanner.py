import re
from pathlib import Path

import yara

from tp2.utils.config import logger

# Extensions des fichiers de regles lus dans le dossier --rules
RULE_EXTENSIONS = (".yar", ".yara", ".rule", ".rules")

# Nos propres regles. Elles sont dans le code (et pas dans un fichier .yar) car la plateforme
# de depot ne garde que les fichiers .py, .toml, .md... dans l'archive.
CUSTOM_RULES = r"""
import "math"

rule Prompt_Injection_Attempt
{
    meta:
        author = "binome TP2"
        description = "Texte qui donne des ordres a une IA pour fausser l'analyse (injection de prompt)"
    strings:
        $ignore_en = /ignore (all |the |any )?(previous|prior|above) (instructions|analysis)/ nocase ascii wide
        $ignore_fr = /ignore[rz]? (les )?instructions/ nocase ascii wide
        $ai_instructions = "AI_INSTRUCTIONS" nocase ascii wide
        $note_to_ai = "NOTE_TO_AI" nocase ascii wide
        $system_prompt = "system prompt" nocase ascii wide
        $mark_clean = /mark (the|this) (sample|file) (as )?(clean|safe)/ nocase ascii wide
    condition:
        any of them
}

rule Registry_Run_Persistence
{
    meta:
        author = "binome TP2"
        description = "Persistance par une cle de registre Run / RunOnce"
        mitre = "T1547.001"
    strings:
        $run = "\\CurrentVersion\\Run" nocase ascii wide
    condition:
        $run
}

rule C2_Gate_Url
{
    meta:
        author = "binome TP2"
        description = "URL de panneau de commande (gate.php, panel.php...) typique d'un C2 HTTP"
        mitre = "T1071.001"
    strings:
        $gate = /https?:\/\/[a-z0-9.\-]{4,}(:[0-9]+)?\/[a-z0-9_\-\/]*(gate|panel|admin|post|upload)\.php/ nocase ascii wide
    condition:
        $gate
}

rule Packed_High_Entropy
{
    meta:
        author = "binome TP2"
        description = "Donnees tres aleatoires (compressees ou chiffrees) : fichier probablement packe"
        mitre = "T1027.002"
    condition:
        filesize > 4096 and (
            math.entropy(0, filesize) >= 7.2 or
            math.entropy(filesize - 4096, 4096) >= 7.5
        )
}
"""

# Noms de nos regles, pour les distinguer des regles fournies par le prof
CUSTOM_RULE_NAMES = re.findall(r"^rule (\w+)", CUSTOM_RULES, re.MULTILINE)


class YaraScanner:
    def __init__(self, rules_dir: str | None = None, use_custom_rules: bool = True) -> None:
        self.rules_dir = rules_dir
        self.use_custom_rules = use_custom_rules
        self.rule_files = []
        self.rules = self._compile_rules()

    def scan(self, data: bytes) -> list[str]:
        """
        Applique toutes les regles YARA sur le contenu d'un fichier

        :param data: contenu brut du fichier
        :return: noms des regles qui matchent, sans doublon
        """
        if self.rules is None:
            return []
        matches = []
        for match in self.rules.match(data=data, timeout=60):
            if match.rule not in matches:
                matches.append(match.rule)
        logger.debug(f"Matches YARA : {matches}")
        return matches

    def _compile_rules(self) -> yara.Rules | None:
        """
        Compile nos regles et celles du dossier --rules. Un fichier de regles invalide est ignore
        (avec un message) pour ne pas bloquer toute l'analyse.
        """
        sources = {}
        if self.use_custom_rules:
            sources["custom"] = CUSTOM_RULES

        for number, rule_file in enumerate(self._find_rule_files()):
            # on lit le fichier nous-memes : yara a du mal avec les accents dans les chemins Windows
            source = rule_file.read_text(encoding="utf-8", errors="replace")
            try:
                yara.compile(source=source)
            except yara.SyntaxError as error:
                logger.error(f"Regles YARA invalides dans {rule_file} : {error}")
                continue
            sources[f"file{number}_{rule_file.stem}"] = source
            self.rule_files.append(str(rule_file))

        if not sources:
            logger.warning("Aucune regle YARA a appliquer")
            return None

        logger.info(f"{len(self.rule_files)} fichier(s) de regles YARA charges depuis {self.rules_dir}")
        return yara.compile(sources=sources)

    def _find_rule_files(self) -> list[Path]:
        """
        Liste les fichiers de regles du dossier --rules (et de ses sous-dossiers)
        """
        if not self.rules_dir:
            return []
        folder = Path(self.rules_dir)
        if not folder.is_dir():
            logger.warning(f"Dossier de regles introuvable : {self.rules_dir}")
            return []
        return sorted(path for path in folder.rglob("*") if path.suffix.lower() in RULE_EXTENSIONS)


def yara_scan(data: bytes, rules_dir: str | None = None) -> list[str]:
    """
    Scanne des donnees avec les regles fournies (rules_dir) et nos propres regles

    :param data: contenu brut du fichier
    :param rules_dir: dossier des regles YARA fournies
    :return: noms des regles qui matchent
    """
    return YaraScanner(rules_dir).scan(data)
