"""
Phase reseau du TP3 : connexion au service revele par la phase web et
decodage des jetons jusqu'au drapeau final. A chaque round, le serveur
envoie base64(XOR(jeton, cle)) ; il faut decoder (base64 puis XOR) et
renvoyer le jeton en clair avant l'echeance.
"""

import base64
import binascii
import socket

from tp3.utils.config import logger

ROUND_TIMEOUT_SECONDS = 5
MAX_ROUNDS = 20


class NetworkPhase:
    """
    Dialogue avec le service TCP revele par la phase web pour decoder
    les jetons et obtenir le drapeau final.
    """

    def __init__(self, host: str, port: int, key: bytes) -> None:
        """
        Initialise la phase reseau.

        :param host: hote du service TCP (fourni par la phase web)
        :param port: port du service TCP (fourni par la phase web)
        :param key: cle de decodage XOR (fournie par la phase web)
        """
        self.host = host
        self.port = port
        self.key = key

    def _decode_token(self, token: bytes) -> bytes:
        """
        Decode un jeton recu : base64 puis XOR avec la cle.

        :param token: jeton brut recu du serveur (encode en base64)
        :return: jeton decode en clair
        :raises binascii.Error: si le jeton n'est pas du base64 valide
        """
        raw = base64.b64decode(token)
        return bytes(byte ^ self.key[index % len(self.key)] for index, byte in enumerate(raw))

    def _read_line(self, connection: socket.socket, buffer: bytes) -> tuple[bytes | None, bytes]:
        """
        Lit une ligne depuis la connexion, tolerant aux fragmentations.

        :param connection: socket connectee au service
        :param buffer: donnees deja recues mais pas encore traitees
        :return: tuple (ligne lue ou None si connexion fermee/timeout, buffer restant)
        """
        while b"\n" not in buffer:
            try:
                chunk = connection.recv(4096)
            except socket.timeout:
                return None, buffer
            if not chunk:
                return None, buffer
            buffer += chunk

        line, _, buffer = buffer.partition(b"\n")
        return line.strip(), buffer

    def run(self) -> str:
        """
        Lit la banniere, puis boucle sur les jetons envoyes par le
        serveur jusqu'au drapeau final.

        :return: drapeau final
        :raises RuntimeError: si la connexion echoue, si le serveur
            signale une erreur, ou si aucun drapeau n'est obtenu
        """
        with socket.create_connection((self.host, self.port), timeout=ROUND_TIMEOUT_SECONDS) as connection:
            connection.settimeout(ROUND_TIMEOUT_SECONDS)
            buffer = b""

            banner, buffer = self._read_line(connection, buffer)
            if banner is None:
                raise RuntimeError("Connexion fermee avant la banniere")
            logger.debug(f"Banniere recue : {banner!r}")

            for _ in range(MAX_ROUNDS):
                line, buffer = self._read_line(connection, buffer)
                if line is None:
                    raise RuntimeError("Connexion fermee sans drapeau final")

                if line.startswith(b"OK "):
                    return line[len(b"OK ") :].decode("utf-8", errors="ignore")

                if line in (b"WRONG", b"TIMEOUT"):
                    raise RuntimeError(f"Le serveur a signale : {line.decode('utf-8', errors='ignore')}")

                try:
                    decoded = self._decode_token(line)
                except (binascii.Error, ValueError):
                    logger.debug("Ligne ignoree (pas un jeton valide)")
                    continue

                connection.sendall(decoded + b"\n")

        raise RuntimeError("Nombre maximal de rounds atteint sans drapeau final")