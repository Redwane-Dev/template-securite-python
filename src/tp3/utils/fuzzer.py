"""
Fuzzing des endpoints web pour localiser les pages candidates du TP3.
"""

from pathlib import Path

import requests

from tp3.utils.config import logger


class Fuzzer:
    """
    Fuzzer simple : teste une liste de chemins sur une cible web et
    retourne tous ceux qui se distinguent d'une page inconnue.
    """

    def __init__(self, target: str, timeout: int = 5) -> None:
        """
        Initialise le fuzzer.

        :param target: URL de base de la cible (ex: http://localhost:8080)
        :param timeout: delai maximum en secondes pour chaque requete
        """
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()

    def _load_wordlist(self) -> list[str]:
        """
        Charge la wordlist embarquee dans le paquet.

        :return: liste des chemins a tester
        """
        wordlist_path = Path(__file__).parent.parent / "assets" / "wordlist.txt"
        with open(wordlist_path, encoding="utf-8") as file:
            return [line.strip() for line in file if line.strip()]

    def _baseline(self) -> tuple[int, int, str]:
        """
        Interroge un chemin aleatoire pour connaitre la reponse "page inconnue".

        :return: tuple (code http, taille du corps, type de contenu) de reference
        """
        response = self.session.get(f"{self.target}/this-path-does-not-exist-xyz", timeout=self.timeout)
        content_type = response.headers.get("Content-Type", "")
        return response.status_code, len(response.content), content_type

    def find_hidden_pages(self) -> list[str]:
        """
        Teste chaque chemin de la wordlist et retourne tous ceux qui se
        distinguent de la reponse de reference (page inconnue).

        :return: liste des chemins candidats, vide si aucun ne se distingue
        """
        baseline_code, baseline_size, baseline_type = self._baseline()
        candidates: list[str] = []

        for path in self._load_wordlist():
            url = f"{self.target}/{path}"
            try:
                response = self.session.get(url, timeout=self.timeout)
            except requests.RequestException as error:
                logger.debug(f"Echec sur {url} : {error}")
                continue

            content_type = response.headers.get("Content-Type", "")
            different_code = response.status_code != baseline_code
            different_size = len(response.content) != baseline_size
            different_type = content_type != baseline_type

            if response.status_code < 400 and (different_code or different_size or different_type):
                logger.info(f"Candidat trouve : {url} (code {response.status_code})")
                candidates.append(path)

        if not candidates:
            logger.error("Aucun candidat trouve avec la wordlist")

        return candidates