"""
Phase web du TP3 : connexion aux pages candidates en resolvant le
captcha, puis extraction du drapeau, de l'hote, du port et de la cle
de la phase reseau depuis la reponse JSON.
"""

import time

import requests

from tp3.utils.captcha import CaptchaSolver
from tp3.utils.config import logger
from tp3.utils.fuzzer import Fuzzer

MAX_ATTEMPTS = 8
RETRY_DELAY_SECONDS = 2


class WebPhase:
    """
    Orchestration de la phase web : fuzzing, captcha, extraction des
    informations necessaires a la phase reseau.
    """

    def __init__(self, target: str, timeout: int = 5) -> None:
        """
        Initialise la phase web.

        :param target: URL de base de la cible
        :param timeout: delai maximum en secondes pour chaque requete
        """
        self.target = target.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.captcha_solver = CaptchaSolver()

    def _visit_candidate(self, page_url: str) -> bool:
        """
        Visite la page candidate pour etablir la session et declencher
        la generation d'un nouveau code captcha cote serveur.

        :param page_url: URL du candidat a tester
        :return: True si la page repond, False sinon
        """
        try:
            response = self.session.get(page_url, timeout=self.timeout)
        except requests.RequestException as error:
            logger.error(f"Impossible d'ouvrir {page_url} : {error}")
            return False
        return response.status_code == 200

    def _get_captcha_image(self) -> bytes | None:
        """
        Recupere l'image du captcha (endpoint commun, pas sous la page candidate).

        :return: octets de l'image, ou None si introuvable
        """
        try:
            response = self.session.get(f"{self.target}/captcha.png", timeout=self.timeout)
        except requests.RequestException as error:
            logger.error(f"Impossible de recuperer le captcha : {error}")
            return None

        if response.status_code != 200:
            return None
        return response.content

    def _submit_captcha(self, page_url: str, value: str) -> requests.Response | None:
        """
        Soumet la valeur du captcha au formulaire de la page candidate.

        :param page_url: URL de la page a tester
        :param value: valeur lue par l'OCR
        :return: reponse HTTP, ou None en cas d'echec reseau
        """
        try:
            return self.session.post(page_url, data={"captcha": value}, timeout=self.timeout)
        except requests.RequestException as error:
            logger.error(f"Echec de soumission du captcha : {error}")
            return None

    def _extract_breach_info(self, response: requests.Response) -> tuple[str, str, int, bytes] | None:
        """
        Extrait le drapeau, l'hote, le port et la cle depuis la reponse JSON
        renvoyee apres un captcha correct.

        :param response: reponse HTTP a la soumission du captcha
        :return: tuple (flag, host, port, key) ou None si incomplet/refuse
        """
        if response.status_code != 200:
            return None

        try:
            data = response.json()
        except ValueError:
            return None

        if not all(field in data for field in ("flag1", "host", "port", "key")):
            return None

        return data["flag1"], data["host"], int(data["port"]), bytes.fromhex(data["key"])

    def _try_candidate(self, page_url: str) -> tuple[str, str, int, bytes] | None:
        """
        Tente de franchir le captcha d'un candidat et d'en extraire les
        informations necessaires a la phase reseau.

        :param page_url: URL du candidat a tester
        :return: tuple (flag, host, port, key) si le candidat est valide, None sinon
        """
        if not self._visit_candidate(page_url):
            return None

        for attempt in range(1, MAX_ATTEMPTS + 1):
            image_bytes = self._get_captcha_image()
            if image_bytes is None:
                time.sleep(RETRY_DELAY_SECONDS)
                continue

            captcha_value = self.captcha_solver.solve(image_bytes)
            response = self._submit_captcha(page_url, captcha_value)
            if response is None:
                time.sleep(RETRY_DELAY_SECONDS)
                continue

            breach_info = self._extract_breach_info(response)
            if breach_info is not None:
                logger.info(f"Candidat {page_url} valide a la tentative {attempt}")
                return breach_info

            logger.warning(f"Tentative {attempt} refusee sur {page_url}")
            self._visit_candidate(page_url)  # nouveau code avant de reessayer
            time.sleep(RETRY_DELAY_SECONDS)

        logger.debug(f"Candidat {page_url} abandonne apres {MAX_ATTEMPTS} tentatives")
        return None

    def run(self) -> tuple[str, str, int, bytes]:
        """
        Enchaine fuzzing et verification de chaque candidat jusqu'a en
        trouver un qui fournit captcha, hote, port et cle valides.

        :return: tuple (flag1, host, port, key)
        :raises RuntimeError: si aucun candidat n'est valide
        """
        fuzzer = Fuzzer(self.target, timeout=self.timeout)
        candidates = fuzzer.find_hidden_pages()
        if not candidates:
            raise RuntimeError("Aucune page candidate trouvee")

        for candidate in candidates:
            page_url = f"{self.target}/{candidate}"
            breach_info = self._try_candidate(page_url)
            if breach_info is not None:
                return breach_info

        raise RuntimeError("Aucun candidat ne fournit captcha, hote, port et cle valides")