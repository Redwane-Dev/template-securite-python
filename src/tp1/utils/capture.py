import re
from collections import Counter, defaultdict
from urllib.parse import unquote

from scapy.all import ARP, IP, TCP, Ether, IPv6, Raw, rdpcap, sniff

from tp1.utils.config import logger
from tp1.utils.lib import build_block_rule, choose_interface, is_http_payload, is_http_request

PORT_SCAN_THRESHOLD = 10
ARP_UNSOLICITED_THRESHOLD = 5

# motifs testés sur le texte décodé et en minuscules
SQL_INJECTION_PATTERNS = [
    r"'\s*or\s+'?\w+'?\s*=\s*'?\w+",
    r"\bor\s+1\s*=\s*1\b",
    r"'\s*and\s+'?\w+'?\s*=\s*'?\w+",
    r"\bunion(\s+all)?\s+select\b",
    r"'\s*;\s*(drop|delete|insert|update|select)\b",
    r"\bdrop\s+table\b",
    r"'\s*(--|#|/\*)",
    r"\bsleep\s*\(\s*\d+\s*\)",
    r"\bbenchmark\s*\(",
    r"\binformation_schema\b",
    r"\bxp_cmdshell\b",
    r"user-agent:\s*sqlmap",
]

FLAG_REGEX = re.compile(r"ESGI\{[^{}\s]{1,200}\}")

# il y a des faux flags dans le pcap, entourés de texte du genre "ignore previous..."
DECOY_WORDS = [
    "ignore",
    "previous",
    "assistant",
    "system prompt",
    "instruction",
    "report exactly",
    "just output",
    "do not analyse",
    "verified flag",
    "correct flag",
    "true attacker",
]

PROTOCOL_NAMES = {
    "Ether": "Ethernet",
    "CookedLinux": "Ethernet",
    "Dot1Q": "VLAN",
    "HTTPRequest": "HTTP",
    "HTTPResponse": "HTTP",
}

IGNORED_LAYERS = ["Raw", "Padding", "NoPayload", "IPerror", "TCPerror", "UDPerror", "ICMPerror"]


class Capture:
    def __init__(self, interface: str | None = None, pcap_file: str | None = None) -> None:
        self.pcap_file = pcap_file
        # pas besoin de demander l'interface si on lit un fichier
        self.interface = "" if pcap_file is not None else choose_interface(interface)
        self.packets = []
        self.protocols = {}
        self.attacks = []
        self.flag = ""
        self.summary = ""

    def capture_traffic(self, count: int = 200, timeout: int = 30) -> None:
        """
        Capture network traffic from an interface
        """
        if self.pcap_file is not None:
            logger.info(f"Lecture du fichier PCAP {self.pcap_file}")
            self.packets = list(rdpcap(self.pcap_file))
        else:
            logger.info(f"Capture traffic from interface {self.interface} ({count} paquets, {timeout}s max)")
            self.packets = list(sniff(iface=self.interface, count=count, timeout=timeout))
        logger.info(f"{len(self.packets)} paquets recuperes")

    def sort_network_protocols(self) -> list[tuple[str, int]]:
        """
        Sort and return all captured network protocols
        """
        if not self.protocols:
            self.get_all_protocols()
        return sorted(self.protocols.items(), key=lambda item: (-item[1], item[0]))

    def get_all_protocols(self) -> dict[str, int]:
        """
        Return all protocols captured with total packets number
        """
        counter = Counter()
        for packet in self.packets:
            counter.update(self._get_protocol_names(packet))
        self.protocols = dict(counter)
        return self.protocols

    def analyse(self, protocols: str = "tcp") -> None:
        """
        Analyse all captured data and return statement
        Si un tra c est illégitime (exemple : Injection SQL, ARP
        Spoo ng, etc)
        a Noter la tentative d'attaque.
        b Relever le protocole ainsi que l'adresse réseau/physique
        de l'attaquant.
        c (FACULTATIF) Opérer le blocage de la machine
        attaquante.
        Sinon a cher que tout va bien
        """
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()
        logger.debug(f"All protocols: {all_protocols}")
        logger.debug(f"Sorted protocols: {sort}")

        self.attacks = self._detect_arp_spoofing() + self._detect_port_scan() + self._detect_sql_injection()
        for attack in self.attacks:
            logger.warning(f"Attaque detectee : {attack['type']} par {attack['attacker']}")

        self.flag = self._search_flag()
        if self.flag:
            logger.info(f"Flag trouve : {self.flag}")
        else:
            logger.info("Aucun flag trouve dans la capture")

        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        """
        Return summary
        :return:
        """
        return self.summary

    def _gen_summary(self) -> str:
        """
        Generate summary
        """
        summary = f"{len(self.packets)} paquets analyses, {len(self.protocols)} protocoles differents.\n"

        if not self.attacks:
            summary += "Aucun trafic illegitime detecte : tout va bien.\n"
        else:
            summary += f"ATTENTION : {len(self.attacks)} attaque(s) detectee(s) !\n"
            for attack in self.attacks:
                summary += (
                    f"- {attack['type']} ({attack['protocol']}) depuis {attack['attacker']} : "
                    f"{attack['details']}\n"
                )

        if self.flag:
            summary += f"Flag trouve dans la capture : {self.flag}\n"
        return summary

    def _get_protocol_names(self, packet) -> list[str]:
        names = []
        for layer_class in packet.layers():
            name = layer_class.__name__
            if name in IGNORED_LAYERS:
                continue
            if name in PROTOCOL_NAMES:
                name = PROTOCOL_NAMES[name]
            elif name.startswith("ICMPv6"):
                name = "ICMPv6"
            elif name.startswith("DHCP6"):
                name = "DHCPv6"
            if name not in names:
                names.append(name)

        # scapy ne détecte pas le HTTP tout seul
        if "HTTP" not in names and packet.haslayer(TCP) and packet.haslayer(Raw):
            if is_http_payload(bytes(packet[Raw].load)):
                names.append("HTTP")
        return names

    def _get_source_ip(self, packet) -> str:
        if packet.haslayer(IP):
            return packet[IP].src
        if packet.haslayer(IPv6):
            return packet[IPv6].src
        return ""

    def _get_destination_ip(self, packet) -> str:
        if packet.haslayer(IP):
            return packet[IP].dst
        if packet.haslayer(IPv6):
            return packet[IPv6].dst
        return ""

    def _detect_arp_spoofing(self) -> list[dict]:
        """
        Cherche les IP annoncées par plusieurs MAC et les réponses ARP que personne n'a demandées
        """
        ip_to_macs = defaultdict(Counter)  # ip -> {mac: nb d'annonces}
        pending_requests = Counter()  # (ip qui demande, ip demandée) -> nb de who-has sans réponse
        unsolicited = Counter()
        total_replies = Counter()
        trusted = Counter()  # mac -> nb de who-has envoyés directement à elle

        for packet in self.packets:
            if not packet.haslayer(ARP):
                continue
            arp = packet[ARP]
            mac = arp.hwsrc.lower()

            if arp.op == 1:
                pending_requests[(arp.psrc, arp.pdst)] += 1
                if packet.haslayer(Ether) and packet[Ether].dst != "ff:ff:ff:ff:ff:ff":
                    trusted[packet[Ether].dst.lower()] += 1
                # ARP gratuit
                if arp.psrc == arp.pdst:
                    ip_to_macs[arp.psrc][mac] += 1
            elif arp.op == 2:
                ip_to_macs[arp.psrc][mac] += 1
                total_replies[mac] += 1
                key = (arp.pdst, arp.psrc)
                if pending_requests[key] > 0:
                    pending_requests[key] -= 1
                else:
                    unsolicited[mac] += 1

        attacks = []
        attacker_macs = []

        for ip, macs in ip_to_macs.items():
            if len(macs) < 2:
                continue
            # le plus suspect = celui qui envoie le plus de réponses non demandées
            best_mac = max(macs, key=lambda m: (unsolicited[m] - trusted[m], total_replies[m]))
            logger.debug(f"Conflit ARP pour {ip} : {dict(macs)}, MAC suspecte {best_mac}")
            if best_mac in attacker_macs:
                continue
            attacker_macs.append(best_mac)
            attacks.append(
                {
                    "type": "arp_spoofing",
                    "attacker": best_mac,
                    "protocol": "ARP",
                    "details": (
                        f"{ip} annoncee par plusieurs MAC ({', '.join(macs)}), "
                        f"{unsolicited[best_mac]} reponses non sollicitees de {best_mac}"
                    ),
                    "block_rule": build_block_rule(best_mac),
                }
            )

        for mac, nb in unsolicited.items():
            if mac in attacker_macs or nb < ARP_UNSOLICITED_THRESHOLD:
                continue
            attacker_macs.append(mac)
            attacks.append(
                {
                    "type": "arp_spoofing",
                    "attacker": mac,
                    "protocol": "ARP",
                    "details": f"{nb} reponses ARP non sollicitees",
                    "block_rule": build_block_rule(mac),
                }
            )
        return attacks

    def _detect_port_scan(self) -> list[dict]:
        """
        Une IP qui envoie des SYN (ou FIN/NULL/XMAS) vers plein de ports différents
        """
        probes = defaultdict(set)  # ip source -> {(ip dst, port)}

        for packet in self.packets:
            if not packet.haslayer(TCP):
                continue
            source_ip = self._get_source_ip(packet)
            if not source_ip:
                continue
            flags = str(packet[TCP].flags)
            is_syn = "S" in flags and "A" not in flags
            if is_syn or flags in ("", "F", "FPU"):
                probes[source_ip].add((self._get_destination_ip(packet), packet[TCP].dport))

        attacks = []
        for source_ip, targets in probes.items():
            ports = {port for _, port in targets}
            hosts = {host for host, _ in targets}
            logger.debug(f"{source_ip} a sonde {len(ports)} ports")
            if len(ports) >= PORT_SCAN_THRESHOLD:
                attacks.append(
                    {
                        "type": "port_scan",
                        "attacker": source_ip,
                        "protocol": "TCP",
                        "details": f"{len(ports)} ports differents sondes sur {', '.join(sorted(hosts))}",
                        "block_rule": build_block_rule(source_ip),
                    }
                )
        return attacks

    def _detect_sql_injection(self) -> list[dict]:
        attacks = []
        attacker_ips = []

        for request in self._get_http_requests():
            text = self._decode_payload(request["data"]).replace("+", " ").lower()
            if not any(re.search(pattern, text) for pattern in SQL_INJECTION_PATTERNS):
                continue

            source_ip = request["source_ip"]
            if source_ip in attacker_ips:
                continue
            attacker_ips.append(source_ip)

            first_line = text.split("\n")[0].strip()
            attacks.append(
                {
                    "type": "sql_injection",
                    "attacker": source_ip,
                    "protocol": "HTTP",
                    "details": f"motif suspect dans la requete '{first_line[:80]}'",
                    "block_rule": build_block_rule(source_ip),
                }
            )
        return attacks

    def _search_flag(self) -> str:
        """
        Il peut y avoir plusieurs flags, on garde celui qui a le meilleur score :
        +3 dans la ligne de requête HTTP, +2 si ça vient d'un attaquant, -5 si c'est un leurre
        """
        attacker_ips = [attack["attacker"] for attack in self.attacks]

        # (texte, ip source, est-ce une requête http)
        candidates = [
            (self._decode_payload(request["data"]), request["source_ip"], True)
            for request in self._get_http_requests()
        ]
        for packet in self.packets:
            if packet.haslayer(Raw) or not packet.haslayer(TCP):
                candidates.append((self._decode_payload(bytes(packet)), self._get_source_ip(packet), False))

        best_flag = ""
        best_score = None
        for text, source_ip, is_request in candidates:
            for match in FLAG_REGEX.finditer(text):
                score = 0
                if is_request and FLAG_REGEX.search(text.split("\n")[0]):
                    score += 3
                if source_ip in attacker_ips:
                    score += 2
                if any(word in text.lower() for word in DECOY_WORDS):
                    score -= 5

                logger.debug(f"Flag candidat {match.group(0)} ({source_ip}) : score {score}")
                if best_score is None or score > best_score:
                    best_score = score
                    best_flag = match.group(0)
        return best_flag

    def _get_http_requests(self) -> list[dict]:
        """
        Reconstruit les flux TCP et garde ceux qui commencent par une requête HTTP
        """
        flows = defaultdict(dict)  # (src, sport, dst, dport) -> {seq: data}

        for packet in self.packets:
            if not packet.haslayer(TCP) or not packet.haslayer(Raw):
                continue
            tcp = packet[TCP]
            key = (self._get_source_ip(packet), tcp.sport, self._get_destination_ip(packet), tcp.dport)
            # setdefault pour ignorer les retransmissions
            flows[key].setdefault(tcp.seq, bytes(packet[Raw].load))

        requests = []
        for key, segments in flows.items():
            data = b"".join(segments[seq] for seq in sorted(segments))
            if is_http_request(data):
                requests.append({"source_ip": key[0], "data": data})
        return requests

    def _decode_payload(self, data: bytes) -> str:
        # deux unquote car certaines requêtes sont encodées deux fois (%2527)
        text = data.decode("latin-1").replace("\r\n", "\n")
        return unquote(unquote(text, encoding="latin-1"), encoding="latin-1")
