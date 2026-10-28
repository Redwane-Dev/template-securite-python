"""
Tests pour la resolution du captcha (CaptchaSolver).
"""

import io
from unittest.mock import patch

from PIL import Image

from tp3.utils.captcha import CaptchaSolver


def _build_captcha_image_bytes() -> bytes:
    """
    Construit une petite image en memoire pour les tests.

    :return: octets PNG d'une image factice
    """
    image = Image.new("RGB", (60, 20), color="white")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def test_given_readable_image_when_solve_then_returns_cleaned_text() -> None:
    # Given
    solver = CaptchaSolver()
    image_bytes = _build_captcha_image_bytes()

    # When
    with patch("tp3.utils.captcha.pytesseract.image_to_string", return_value="ab12\n"):
        result = solver.solve(image_bytes)

    # Then
    assert result == "AB12"


def test_given_unreadable_image_when_solve_then_returns_empty_string() -> None:
    # Given
    solver = CaptchaSolver()
    image_bytes = _build_captcha_image_bytes()

    # When
    with patch("tp3.utils.captcha.pytesseract.image_to_string", return_value=""):
        result = solver.solve(image_bytes)

    # Then
    assert result == ""