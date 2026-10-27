import re

from tp1.utils.config import logger

HTTP_METHODS = (
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
)

MAC_ADDRESS_REGEX = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


def hello_world() -> str:
    """
    Hello world function

    :return: "hello world"
    """
    return "hello world"


def choose_interface(interface: str | None = None) -> str:
    """
    Return network interface and input user choice

    :return: network interface
    """
    if interface:
        logger.info(f"Interface choisie en argument : {interface}")
        return interface

    from scapy.all import conf, get_working_ifaces

    interfaces = get_working_ifaces()
    default_interface = str(conf.iface)

    if len(interfaces) == 0:
        logger.warning(f"Aucune interface trouvee, utilisation de l'interface par defaut {default_interface}")
        return default_interface

    logger.info("Interfaces reseau disponibles :")
    for i, iface in enumerate(interfaces):
        logger.info(f"  [{i}] {iface.name} - {iface.description}")

    answer = input(f"Numero de l'interface a ecouter (vide = {default_interface}) : ").strip()
    if answer == "":
        logger.info(f"Interface par defaut choisie : {default_interface}")
        return default_interface

    if not answer.isdigit() or int(answer) >= len(interfaces):
        logger.warning(f"Choix '{answer}' invalide, utilisation de {default_interface}")
        return default_interface

    chosen_interface = interfaces[int(answer)].name
    logger.info(f"Interface choisie : {chosen_interface}")
    return chosen_interface


def is_http_request(payload: bytes) -> bool:
    return payload.startswith(HTTP_METHODS)


def is_http_payload(payload: bytes) -> bool:
    return is_http_request(payload) or payload.startswith((b"HTTP/1.", b"HTTP/2"))


def is_mac_address(value: str) -> bool:
    return MAC_ADDRESS_REGEX.match(value) is not None


def build_block_rule(attacker: str) -> str:
    # pour une MAC on ne peut bloquer que sous linux (arptables / iptables -m mac)
    if is_mac_address(attacker):
        return (
            f"arptables -A INPUT --source-mac {attacker} -j DROP ; "
            f"iptables -A INPUT -m mac --mac-source {attacker} -j DROP"
        )

    linux_rule = f"iptables -A INPUT -s {attacker} -j DROP"
    windows_rule = (
        f'netsh advfirewall firewall add rule name="IDS-TP1 block {attacker}" '
        f"dir=in action=block remoteip={attacker}"
    )
    return f"{linux_rule} ; {windows_rule}"
