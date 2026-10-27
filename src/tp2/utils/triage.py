from pathlib import Path

from tp2.utils.analyzer import (
    extract_iocs,
    extract_strings,
    find_flag,
    find_injections,
    find_suspicious_apis,
    get_file_metadata,
    parse_binary,
    shannon_entropy,
)
from tp2.utils.config import logger
from tp2.utils.llm import LLMClient, build_summary, llm_triage
from tp2.utils.scanner import CUSTOM_RULE_NAMES, YaraScanner

PACKED_ENTROPY = 7.2
PACKER_SECTION_NAMES = ("upx", ".aspack", ".packed", ".mpress", ".themida", ".vmp")

# Capacites reconnues a partir des API / chaines trouvees dans le fichier
CAPABILITIES = [
    {
        "name": "telechargement et execution de charge (downloader)",
        "apis": {
            "URLDownloadToFileA",
            "URLDownloadToFileW",
            "WinExec",
            "ShellExecuteA",
            "ShellExecuteW",
            "ShellExecuteExA",
            "InternetOpenUrlA",
            "InternetOpenUrlW",
            "InternetReadFile",
        },
        "strings": {"urlmon.dll", "wininet.dll"},
        "family": "dropper",
        "mitre": ["T1105", "T1106"],
    },
    {
        "name": "shell distant / connexion reseau (backdoor)",
        "apis": {"WSASocketA", "WSASocketW", "WSAStartup", "connect", "bind", "listen", "accept"},
        "strings": {"ws2_32.dll", "cmd.exe", "/bin/sh", "/bin/bash"},
        "family": "backdoor",
        "mitre": ["T1059.003", "T1095"],
    },
    {
        "name": "capture du clavier (keylogger)",
        "apis": {"SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState"},
        "strings": set(),
        "family": "keylogger",
        "mitre": ["T1056.001"],
    },
    {
        "name": "injection dans un autre processus",
        "apis": {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection"},
        "strings": set(),
        "family": "trojan",
        "mitre": ["T1055"],
    },
    {
        "name": "creation de processus",
        "apis": {"CreateProcessA", "CreateProcessW", "execve", "system", "popen"},
        "strings": set(),
        "family": "trojan",
        "mitre": ["T1106"],
    },
    {
        "name": "detection de debogueur",
        "apis": {"IsDebuggerPresent", "CheckRemoteDebuggerPresent"},
        "strings": set(),
        "family": "trojan",
        "mitre": ["T1622"],
    },
]

# Ordre de priorite des familles quand plusieurs capacites sont presentes
FAMILY_PRIORITY = ["keylogger", "backdoor", "dropper", "packed", "trojan"]

OUTPUT_IOC_KEYS = ["domains", "ips", "urls", "mutex", "registry"]


class SampleTriage:
    def __init__(self, path: str, scanner: YaraScanner, llm_client: LLMClient | None = None) -> None:
        self.path = path
        self.scanner = scanner
        self.llm_client = llm_client
        self.result = {}

    def run(self) -> dict:
        """
        Analyse complete d'un echantillon : metadonnees, IOC, structure, YARA, capacites, verdict

        :return: resultats complets (le JSON final est produit par to_output)
        """
        logger.info(f"Analyse de {self.path}")
        with open(self.path, "rb") as sample_file:
            data = sample_file.read()

        result = get_file_metadata(data)
        result["name"] = Path(self.path).name
        result["iocs"] = extract_iocs(data)

        binary = parse_binary(self.path)
        result["format"] = binary["format"]
        result["libraries"] = binary["libraries"]
        result["exports"] = binary["exports"]
        result["sections"] = binary["sections"]
        result["overlay_size"] = binary["overlay_size"]
        result["suspicious_apis"] = find_suspicious_apis(data)
        # les API suspectes trouvees dans les chaines d'abord, puis la table d'imports
        result["imports"] = list(dict.fromkeys(result["suspicious_apis"] + binary["imports"]))
        result["high_entropy_sections"] = [
            section["name"] for section in binary["sections"] if section["entropy"] >= PACKED_ENTROPY
        ]

        result["yara_matches"] = self.scanner.scan(data)
        injections = find_injections(data)
        result["injection_count"] = len(injections)
        if injections:
            logger.warning(
                f"{len(injections)} tentative(s) d'injection de prompt ignoree(s) dans {self.path}"
            )

        result["packed"] = self._is_packed(data, result)
        strings = {text.lower() for text in extract_strings(data)}
        capabilities, families, mitre = self._detect_capabilities(result, strings)
        result["capabilities"] = capabilities
        result["flag"] = find_flag(data)

        deterministic_family = self._deterministic_family(families, result)
        deterministic_score = self._deterministic_score(result, families)
        result["deterministic_score"] = deterministic_score

        verdict = None
        if self.llm_client is not None:
            verdict = llm_triage(build_summary(result), self.llm_client)
        self._merge_verdict(result, verdict, deterministic_family, deterministic_score, mitre)

        self.result = result
        logger.info(
            f"{result['name']} : famille {result['family_guess']}, score {result['score']}/10, "
            f"flag {result['flag'] or 'aucun'}"
        )
        return result

    def to_output(self) -> dict:
        """
        Resultat au format JSON attendu par la correction automatique

        :return: dictionnaire avec exactement les cles demandees
        """
        result = self.result
        return {
            "sha256": result["sha256"],
            "md5": result["md5"],
            "size": result["size"],
            "entropy": result["entropy"],
            "file_type": result["file_type"],
            "iocs": {key: result["iocs"].get(key, []) for key in OUTPUT_IOC_KEYS},
            "imports": result["imports"],
            "yara_matches": result["yara_matches"],
            "family_guess": result["family_guess"],
            "mitre_attack": result["mitre_attack"],
            "llm_summary": result["llm_summary"],
            "score": result["score"],
            "flag": result["flag"],
        }

    def _is_packed(self, data: bytes, result: dict) -> bool:
        """
        Un fichier est considere comme packe si ses donnees sont tres aleatoires (entropie),
        si une section ou l'overlay est tres aleatoire, ou si une section porte le nom d'un packer
        """
        if result["entropy"] >= PACKED_ENTROPY or result["high_entropy_sections"]:
            return True
        if (
            result["overlay_size"] > 1024
            and shannon_entropy(data[-result["overlay_size"] :]) >= PACKED_ENTROPY
        ):
            return True
        if any(section["name"].lower().startswith(PACKER_SECTION_NAMES) for section in result["sections"]):
            return True
        return "Packed_High_Entropy" in result["yara_matches"]

    def _detect_capabilities(self, result: dict, strings: set[str]) -> tuple[list[str], list[str], list[str]]:
        """
        Deduit les capacites du malware a partir des API, chaines et IOC trouves

        :return: (capacites, familles correspondantes, techniques MITRE ATT&CK)
        """
        capabilities = []
        families = []
        mitre = []
        apis = set(result["suspicious_apis"])

        for capability in CAPABILITIES:
            found_strings = {text.lower() for text in capability["strings"]} & strings
            if apis & capability["apis"] or found_strings:
                capabilities.append(capability["name"])
                families.append(capability["family"])
                mitre.extend(capability["mitre"])

        iocs = result["iocs"]
        if iocs["urls"] or iocs["domains"] or iocs["ips"]:
            capabilities.append("communication avec un serveur de commande (C2)")
            mitre.append("T1071.001" if iocs["urls"] else "T1071")
        if any("\\run" in key.lower() for key in iocs["registry"]):
            capabilities.append("persistance par cle de registre Run")
            mitre.append("T1547.001")
        elif iocs["registry"]:
            capabilities.append("modification du registre")
            mitre.append("T1112")
        if iocs["mutex"]:
            capabilities.append("mutex (une seule instance du malware)")
        if result["packed"]:
            capabilities.append("code packe / chiffre")
            families.append("packed")
            mitre.append("T1027.002")
        if result["injection_count"]:
            capabilities.append("tentative de manipulation de l'analyse (injection de prompt)")

        return capabilities, families, list(dict.fromkeys(mitre))

    def _deterministic_family(self, families: list[str], result: dict) -> str:
        """
        Famille la plus probable sans LLM, selon l'ordre de priorite FAMILY_PRIORITY
        """
        for family in FAMILY_PRIORITY:
            if family in families:
                return family
        iocs = result["iocs"]
        if any(iocs[key] for key in OUTPUT_IOC_KEYS):
            return "trojan"
        return "unknown"

    def _deterministic_score(self, result: dict, families: list[str]) -> int:
        """
        Score de 0 a 10 calcule uniquement avec les regles (YARA, IOC, capacites).
        Il sert de plancher : le LLM ne peut pas faire baisser le score en dessous.
        """
        score = 0
        if {"keylogger", "backdoor", "dropper"} & set(families):
            score += 3
        score += min(families.count("trojan"), 2)
        iocs = result["iocs"]
        if iocs["urls"] or iocs["domains"] or iocs["ips"]:
            score += 1
        if iocs["registry"]:
            score += 1
        if iocs["mutex"]:
            score += 1
        if result["packed"]:
            score += 2
        if result["injection_count"]:
            score += 1
        # une regle fournie par le prof qui matche ajoute un point (les notres sont deja comptees au-dessus)
        if any(match not in CUSTOM_RULE_NAMES for match in result["yara_matches"]):
            score += 1
        return min(score, 10)

    def _merge_verdict(
        self,
        result: dict,
        verdict: dict | None,
        family: str,
        score: int,
        mitre: list[str],
    ) -> None:
        """
        Combine le verdict des regles et celui du LLM. Le LLM ne decide jamais seul :
        - la famille trouvee par les regles est prioritaire,
        - le score ne peut pas descendre sous le score des regles,
        - les IOC restent ceux extraits par l'outil.
        """
        if verdict is None:
            result["family_guess"] = family
            result["mitre_attack"] = mitre
            result["score"] = score
            result["llm_summary"] = self._fallback_summary(result, family, score)
            result["verdict_source"] = "regles (LLM indisponible)"
            return

        result["family_guess"] = family if family != "unknown" else verdict["family"]
        result["mitre_attack"] = list(dict.fromkeys(mitre + verdict["mitre_attack"]))
        result["score"] = max(score, round((2 * score + verdict["score"]) / 3))
        summary = verdict["summary"]
        if result["injection_count"] and "injection" not in summary.lower():
            summary += f" {result['injection_count']} tentative(s) d'injection de prompt ignoree(s)."
        result["llm_summary"] = summary
        result["verdict_source"] = f"regles + LLM ({self.llm_client.backend})"

    def _fallback_summary(self, result: dict, family: str, score: int) -> str:
        """
        Resume ecrit sans LLM (repli deterministe, par exemple pendant la correction hors ligne)
        """
        if score == 0:
            return "Aucun indicateur malveillant trouve par l'analyse statique : fichier probablement sain."

        parts = [f"Fichier {result['file_type'].split(',')[0]} classe comme {family} (score {score}/10)."]
        if result["capabilities"]:
            parts.append(f"Capacites : {', '.join(result['capabilities'])}.")
        iocs = result["iocs"]
        network = iocs["domains"] + iocs["ips"]
        if network:
            parts.append(f"Infrastructure reseau : {', '.join(network[:5])}.")
        if result["yara_matches"]:
            parts.append(f"Regles YARA : {', '.join(result['yara_matches'])}.")
        if result["injection_count"]:
            parts.append(
                f"{result['injection_count']} texte(s) tentant de manipuler l'analyse ont ete ignores."
            )
        return " ".join(parts)
