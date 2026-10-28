"""
Resolution du captcha image protegeant la page cachee du TP3.
"""

import io

import pytesseract
from PIL import Image, ImageOps

from tp3.utils.config import logger


class CaptchaSolver:
    """
    Pretraite une image de captcha et tente d'en extraire le texte par OCR.
    """

    def __init__(self) -> None:
        """
        Initialise le solveur de captcha.
        """
        self.whitelist = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

    def _preprocess_variants(self, image: Image.Image) -> list[Image.Image]:
        """
        Genere quelques variantes pretraitees de l'image pour ameliorer l'OCR.

        :param image: image brute du captcha
        :return: liste d'images pretraitees (seuillage, inversion, agrandissement)
        """
        grayscale = ImageOps.grayscale(image)
        threshold = grayscale.point(lambda pixel: 255 if pixel > 140 else 0)
        inverted = ImageOps.invert(threshold.convert("L"))
        resized = threshold.resize((threshold.width * 2, threshold.height * 2))
        return [threshold, inverted, resized]

    def solve(self, image_bytes: bytes) -> str:
        """
        Resout un captcha a partir des octets de l'image.

        :param image_bytes: contenu brut de l'image du captcha
        :return: texte reconnu en majuscules, chaine vide si rien n'est lisible
        """
        image = Image.open(io.BytesIO(image_bytes))

        for variant in self._preprocess_variants(image):
            for psm in (7, 8):
                config = f"--psm {psm} -c tessedit_char_whitelist={self.whitelist}"
                text = pytesseract.image_to_string(variant, config=config).strip().upper()
                cleaned = "".join(char for char in text if char in self.whitelist)
                if cleaned:
                    logger.debug(f"Captcha lu (psm {psm}) : {cleaned}")
                    return cleaned

        logger.warning("Impossible de lire le captcha sur cette tentative")
        return ""