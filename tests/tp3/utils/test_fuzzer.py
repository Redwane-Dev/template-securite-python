"""
Tests pour le fuzzer d'endpoints (Fuzzer).
"""

from unittest.mock import MagicMock, patch

from tp3.utils.fuzzer import Fuzzer


def _make_response(status_code: int, body: bytes, content_type: str) -> MagicMock:
    """
    Construit une fausse reponse HTTP pour les tests.

    :param status_code: code HTTP a renvoyer
    :param body: corps de la reponse
    :param content_type: en-tete Content-Type a renvoyer
    :return: objet simulant une reponse requests
    """
    response = MagicMock()
    response.status_code = status_code
    response.content = body
    response.headers = {"Content-Type": content_type}
    return response


def test_given_one_distinct_path_when_find_hidden_pages_then_returns_it() -> None:
    # Given
    fuzzer = Fuzzer("http://127.0.0.1:8080")
    baseline = _make_response(404, b"not found", "text/html")
    found = _make_response(200, b"internal panel", "text/html")

    with (
        patch.object(fuzzer, "_load_wordlist", return_value=["internal-panel", "other"]),
        patch.object(fuzzer.session, "get", side_effect=[baseline, found, baseline]),
    ):
        # When
        candidates = fuzzer.find_hidden_pages()

    # Then
    assert candidates == ["internal-panel"]


def test_given_no_distinct_path_when_find_hidden_pages_then_returns_empty_list() -> None:
    # Given
    fuzzer = Fuzzer("http://127.0.0.1:8080")
    baseline = _make_response(404, b"not found", "text/html")
    same_as_baseline = _make_response(404, b"not found", "text/html")

    with (
        patch.object(fuzzer, "_load_wordlist", return_value=["other"]),
        patch.object(fuzzer.session, "get", side_effect=[baseline, same_as_baseline]),
    ):
        # When
        candidates = fuzzer.find_hidden_pages()

    # Then
    assert candidates == []