import base64
import hashlib
import io
import math
import re
import sys
from collections import Counter

import lief

from tp2.utils.config import logger

# lief affiche ses erreurs dans la console, on prefere passer par notre logger
lief.logging.disable()

MIN_STRING_LENGTH = 4

# --- Indicateurs de compromission (IOC) ---
# (?<![.\w-]) : on ignore les noms qui suivent un point, comme les sections ELF (.data.rel.ro)
DOMAIN_REGEX = re.compile(
    r"(?<![.\w-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.IGNORECASE
)
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_REGEX = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>\x00]+", re.IGNORECASE)
MUTEX_REGEX = re.compile(r"\b(?:Global|Local|Session\\\d+)\\[A-Za-z0-9_.{}\-]+")
REGISTRY_REGEX = re.compile(
    r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|HKLM|HKCU|HKCR|HKU)"
    r"\\[^\x00\r\n\"'<>|]+",
)
WINDOWS_PATH_REGEX = re.compile(r"(?:\b[A-Za-z]:\\|%[A-Za-z]+%\\)[^\x00\r\n\"'<>|*?]+")
UNIX_PATH_REGEX = re.compile(r"(?<![\w/])/(?:tmp|etc|var|home|root|dev/shm|opt|usr/local)/[^\s\x00\"'<>]*")
FLAG_REGEX = re.compile(r"ESGI\{[^{}\s]{1,200}\}")
BASE64_REGEX = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")

# Extensions de fichiers qui ressemblent a des domaines (ws2_32.dll, gate.php, libc.so...)
FILE_EXTENSIONS = {
    "dll", "exe", "sys", "bat", "cmd", "ps1", "vbs", "js", "py", "php", "asp", "aspx", "jsp", "html", "htm",
    "txt", "log", "ini", "cfg", "conf", "json", "xml", "yml", "yaml", "dat", "bin", "tmp", "so", "o", "a",
    "c", "h", "cpp", "md", "gz", "xz", "zip", "rar", "jpg", "png", "gif", "pdf", "doc", "docx", "xls", "lnk",
}  # fmt: skip

# Domaines de plus de 2 lettres acceptes (les extensions pays a 2 lettres sont toutes acceptees)
COMMON_TLDS = {
    "com", "net", "org", "info", "biz", "xyz", "top", "online", "site", "club", "live", "pro", "app", "dev",
    "cloud", "shop", "store", "tech", "space", "website", "icu", "onion", "test", "example", "local",
    "invalid", "lan", "corp", "internal", "home", "gov", "edu", "mil", "int", "name", "mobi", "work", "link",
}  # fmt: skip

# Domaines legitimes qu'on trouve dans beaucoup de binaires (licences, aide en ligne...)
BENIGN_DOMAINS = {
    "gnu.org", "translationproject.org", "fsf.org", "gnome.org", "python.org", "kernel.org", "w3.org",
    "microsoft.com", "windowsupdate.com", "digicert.com", "verisign.com", "sectigo.com", "globalsign.com",
    "openssl.org", "apache.org", "mozilla.org", "sourceware.org", "freedesktop.org",
}  # fmt: skip

# Phrases d'injection de prompt : un texte qui s'adresse a une IA plutot qu'a un programme
INJECTION_PATTERNS = [
    r"ignore\s+(?:all\s+|the\s+|any\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|analysis|rules)",
    r"ignore[sz]?\s+(?:les\s+)?instructions",
    r"disregard\s+(?:all\s+|the\s+|any\s+)?(?:previous|extracted|above|prior)",
    r"\bai[_ ]instructions?\b",
    r"\bnote[_ ]to[_ ](?:ai|llm|assistant|model)\b",
    r"\bsystem\s*prompt\b",
    r"\bas\s+an?\s+(?:ai|llm|language\s+model|assistant)\b",
    r"\byou\s+are\s+(?:now\s+)?(?:an?\s+)?(?:ai|assistant|chatbot)\b",
    r"\bmark\s+(?:the|this)\s+(?:sample|file|binary)\s+(?:as\s+)?(?:clean|safe|benign)",
    r"\b(?:this|the)\s+(?:file|sample|binary)\s+is\s+(?:clean|safe|benign|harmless)",
    r"\bdo\s+not\s+report\b",
    r"\breport\s+only\s+this\b",
    r"\bhoneypot\b.{0,30}\bignore\b",
    r"d[ée]clare[rz]?\s+ce\s+fichier\s+sain",
    r"\bscore\s*[:=]?\s*0\b.{0,40}\b(?:clean|sain)",
]

# API Windows / fonctions reseau souvent utilisees par les malwares
SUSPICIOUS_APIS = {
    "URLDownloadToFileA", "URLDownloadToFileW", "WinExec", "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA",
    "CreateProcessA", "CreateProcessW", "CreateRemoteThread", "VirtualAlloc", "VirtualAllocEx",
    "WriteProcessMemory", "ReadProcessMemory", "OpenProcess", "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
    "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState", "GetForegroundWindow",
    "WSAStartup", "WSASocketA", "WSASocketW", "socket", "connect", "bind", "listen", "accept", "send", "recv",
    "InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW", "InternetReadFile",
    "HttpSendRequestA", "HttpOpenRequestA", "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA",
    "RegOpenKeyExA", "CreateMutexA", "CreateMutexW", "CryptEncrypt", "CryptAcquireContextA",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtUnmapViewOfSection", "AdjustTokenPrivileges",
    "CreateServiceA", "StartServiceA", "CreateToolhelp32Snapshot", "Process32First", "Process32Next",
    "execve", "fork", "ptrace", "system", "popen",
}  # fmt: skip


def get_file_metadata(data: bytes) -> dict:
    """
    Calcule les empreintes et les informations generales d'un fichier

    :param data: contenu brut du fichier
    :return: sha256, md5, taille, type de fichier et entropie de Shannon
    """
    metadata = {
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "size": len(data),
        "file_type": _detect_file_type(data),
        "entropy": round(shannon_entropy(data), 2),
    }
    logger.debug(f"Metadonnees : {metadata}")
    return metadata


def shannon_entropy(data: bytes) -> float:
    """
    Entropie de Shannon en bits par octet (0 = toujours le meme octet, 8 = completement aleatoire)

    :param data: octets a mesurer
    :return: entropie entre 0 et 8
    """
    if not data:
        return 0.0
    total = len(data)
    entropy = 0.0
    for count in Counter(data).values():
        probability = count / total
        entropy -= probability * math.log2(probability)
    return entropy


def extract_strings(data: bytes, min_length: int = MIN_STRING_LENGTH) -> list[str]:
    """
    Extrait les chaines lisibles du fichier, comme la commande `strings` (ASCII puis UTF-16LE)

    :param data: contenu brut du fichier
    :param min_length: longueur minimale d'une chaine
    :return: liste des chaines dans l'ordre du fichier, sans doublon
    """
    ascii_strings = re.findall(rb"[\x20-\x7e]{" + str(min_length).encode() + rb",}", data)
    utf16_strings = re.findall(rb"(?:[\x20-\x7e]\x00){" + str(min_length).encode() + rb",}", data)

    strings = []
    seen = set()
    for raw in ascii_strings:
        text = raw.decode("ascii")
        if text not in seen:
            seen.add(text)
            strings.append(text)
    for raw in utf16_strings:
        text = raw.decode("utf-16le")
        if text not in seen:
            seen.add(text)
            strings.append(text)
    return strings


def is_prompt_injection(text: str) -> bool:
    """
    Indique si une chaine essaie de donner des ordres a une IA (injection de prompt)

    :param text: chaine extraite du fichier
    :return: True si la chaine ressemble a une injection
    """
    lower_text = text.lower()
    return any(re.search(pattern, lower_text) for pattern in INJECTION_PATTERNS)


def find_injections(data: bytes) -> list[str]:
    """
    Liste les chaines du fichier qui ressemblent a une injection de prompt

    :param data: contenu brut du fichier
    :return: chaines suspectes
    """
    return [text for text in extract_strings(data) if is_prompt_injection(text)]


def extract_iocs(data: bytes) -> dict[str, list[str]]:
    """
    Extrait les IOC du fichier : domaines, IP, URLs, mutex, cles de registre et chemins.
    Les chaines qui sont des injections de prompt sont ignorees (leurs IOC ne sont pas fiables).

    :param data: contenu brut du fichier
    :return: dictionnaire {type d'IOC: liste de valeurs}
    """
    iocs = {"domains": [], "ips": [], "urls": [], "mutex": [], "registry": [], "paths": []}

    for text in extract_strings(data):
        if is_prompt_injection(text):
            logger.debug(f"Chaine ignoree (injection) : {text[:80]}")
            continue

        for url in URL_REGEX.findall(text):
            url = url.rstrip(").,;'\"")
            domain = _get_url_host(url)
            if domain and not _is_benign_domain(domain):
                _add_unique(iocs["urls"], url)
                if _is_valid_domain(domain):
                    _add_unique(iocs["domains"], domain)

        for match in DOMAIN_REGEX.finditer(text):
            # un domaine colle a un "@" est une adresse mail, on garde quand meme le domaine
            domain = match.group(0).lower()
            if _is_valid_domain(domain) and not _is_benign_domain(domain):
                _add_unique(iocs["domains"], domain)

        for ip in IP_REGEX.findall(text):
            if _is_valid_ip(ip):
                _add_unique(iocs["ips"], ip)

        for mutex in MUTEX_REGEX.findall(text):
            _add_unique(iocs["mutex"], mutex)

        for key in REGISTRY_REGEX.findall(text):
            _add_unique(iocs["registry"], key.strip())

        for path in WINDOWS_PATH_REGEX.findall(text) + UNIX_PATH_REGEX.findall(text):
            _add_unique(iocs["paths"], path.strip())

    logger.debug(f"IOC extraits : {iocs}")
    return iocs


def find_suspicious_apis(data: bytes) -> list[str]:
    """
    Cherche dans les chaines du fichier les noms d'API souvent utilisees par les malwares

    :param data: contenu brut du fichier
    :return: noms d'API trouves, dans l'ordre du fichier
    """
    return [text for text in extract_strings(data, 3) if text in SUSPICIOUS_APIS]


def find_flag(data: bytes) -> str:
    """
    Cherche le flag ESGI{...}. Plusieurs flags peuvent etre presents (leurres) : chaque candidat
    recoit un score et le meilleur gagne. Un flag dans une injection de prompt est un leurre.

    :param data: contenu brut du fichier
    :return: le flag, ou une chaine vide
    """
    candidates = []
    for text in extract_strings(data):
        candidates.append(text)
        # le flag peut aussi etre cache en base64
        for encoded in BASE64_REGEX.findall(text):
            decoded = _decode_base64(encoded)
            if decoded:
                candidates.append(decoded)

    best_flag = ""
    best_score = None
    for text in candidates:
        for match in FLAG_REGEX.finditer(text):
            score = 0
            if is_prompt_injection(text):
                score -= 10
            before = text[: match.start()].lower()
            if before.rstrip().endswith(("flag=", "flag:", "flag")):
                score += 2
            logger.debug(f"Flag candidat {match.group(0)} : score {score}")
            if best_score is None or score > best_score:
                best_score = score
                best_flag = match.group(0)
    return best_flag


def parse_binary(path: str) -> dict:
    """
    Analyse la structure d'un executable (PE ou ELF) avec lief : imports, exports, sections

    :param path: chemin du fichier
    :return: format, imports, exports, bibliotheques, sections (nom, taille, entropie), taille de l'overlay
    """
    result = {
        "format": "unknown",
        "imports": [],
        "exports": [],
        "libraries": [],
        "sections": [],
        "overlay_size": 0,
    }

    with open(path, "rb") as sample_file:
        data = sample_file.read()

    # lief recoit les octets et pas le chemin : il n'aime pas les accents dans les chemins Windows
    binary = lief.parse(io.BytesIO(data))
    if binary is None:
        logger.info(f"{path} n'est pas un executable reconnu par lief")
        return result

    result["format"] = str(binary.format).split(".")[-1]
    result["imports"] = _unique_names(function.name for function in binary.imported_functions)
    result["exports"] = _unique_names(function.name for function in binary.exported_functions)
    result["libraries"] = _unique_names(str(library) for library in binary.libraries)
    for section in binary.sections:
        if not section.name:
            continue
        result["sections"].append(
            {"name": section.name, "size": section.size, "entropy": round(section.entropy, 2)}
        )
    try:
        result["overlay_size"] = len(binary.overlay)
    except (AttributeError, RuntimeError):
        result["overlay_size"] = 0

    logger.debug(f"{path} : {result['format']}, {len(result['imports'])} imports")
    return result


def _detect_file_type(data: bytes) -> str:
    """
    Type du fichier avec python-magic (libmagic). Sous Windows libmagic n'est souvent pas installe
    (l'import bloque), on reconnait alors nous-memes les formats courants.
    """
    if sys.platform != "win32":
        try:
            import magic

            return magic.from_buffer(data)
        except (ImportError, OSError) as error:
            logger.warning(f"python-magic indisponible ({error}), detection simplifiee")
    return _guess_file_type(data)


def _guess_file_type(data: bytes) -> str:
    """
    Detection simplifiee du type de fichier a partir des premiers octets (magic numbers)
    """
    if data.startswith(b"\x7fELF") and len(data) > 20:
        bits = "64-bit" if data[4] == 2 else "32-bit"
        endian = "LSB" if data[5] == 1 else "MSB"
        file_types = {1: "relocatable", 2: "executable", 3: "pie executable", 4: "core file"}
        elf_type = file_types.get(int.from_bytes(data[16:18], "little"), "file")
        machines = {3: "Intel 80386", 40: "ARM", 62: "x86-64", 183: "ARM aarch64"}
        machine = machines.get(int.from_bytes(data[18:20], "little"), "unknown arch")
        return f"ELF {bits} {endian} {elf_type}, {machine}"

    if data.startswith(b"MZ") and len(data) > 0x40:
        pe_offset = int.from_bytes(data[0x3C:0x40], "little")
        if data[pe_offset : pe_offset + 4] == b"PE\x00\x00":
            magic_number = int.from_bytes(data[pe_offset + 24 : pe_offset + 26], "little")
            kind = "PE32+ executable" if magic_number == 0x20B else "PE32 executable"
            dll = int.from_bytes(data[pe_offset + 22 : pe_offset + 24], "little") & 0x2000
            return f"{kind} (DLL)" if dll else kind
        return "MS-DOS executable"

    signatures = [
        (b"%PDF", "PDF document"),
        (b"PK\x03\x04", "Zip archive data"),
        (b"\x1f\x8b", "gzip compressed data"),
        (b"#!", "script text executable"),
        (b"\xca\xfe\xba\xbe", "Mach-O universal binary"),
        (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit executable"),
    ]
    for signature, name in signatures:
        if data.startswith(signature):
            return name

    if data and all(byte in b"\t\n\r" or 0x20 <= byte < 0x7F for byte in data[:4096]):
        return "ASCII text"
    return "data"


def _get_url_host(url: str) -> str:
    """
    Renvoie le nom d'hote d'une URL (sans port ni identifiants)
    """
    host = url.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0]
    host = host.rsplit("@", 1)[-1].split(":", 1)[0]
    return host.lower()


def _is_valid_domain(domain: str) -> bool:
    """
    Un domaine valide se termine par une extension connue et n'est pas un nom de fichier (ws2_32.dll)
    """
    if IP_REGEX.fullmatch(domain):
        return False
    tld = domain.rsplit(".", 1)[-1].lower()
    if tld in FILE_EXTENSIONS:
        return False
    return len(tld) == 2 or tld in COMMON_TLDS


def _is_benign_domain(domain: str) -> bool:
    """
    Indique si un domaine (ou un de ses parents) fait partie des domaines legitimes connus
    """
    domain = domain.lower()
    return any(domain == benign or domain.endswith(f".{benign}") for benign in BENIGN_DOMAINS)


def _is_valid_ip(ip: str) -> bool:
    """
    Garde les IPv4 correctes et utiles (pas 0.0.0.0, pas de boucle locale, pas de broadcast)
    """
    numbers = [int(part) for part in ip.split(".")]
    if any(number > 255 for number in numbers):
        return False
    if numbers[0] in (0, 127) or numbers[0] >= 224:
        return False
    return True


def _decode_base64(encoded: str) -> str:
    """
    Decode une chaine base64 si elle donne du texte lisible, sinon renvoie une chaine vide
    """
    try:
        decoded = base64.b64decode(encoded + "=" * (-len(encoded) % 4), validate=True)
    except ValueError:
        return ""
    if decoded and all(0x20 <= byte < 0x7F for byte in decoded):
        return decoded.decode("ascii")
    return ""


def _unique_names(names) -> list[str]:
    """
    Enleve les noms vides et les doublons en gardant l'ordre
    """
    result = []
    for name in names:
        if name and name not in result:
            result.append(name)
    return result


def _add_unique(values: list[str], value: str) -> None:
    """
    Ajoute une valeur a une liste si elle n'y est pas deja
    """
    if value and value not in values:
        values.append(value)
