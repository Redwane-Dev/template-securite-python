"""
Tests pour l'orchestration de la phase web (WebPhase).
"""

from unittest.mock import MagicMock, patch

import pytest

from tp3.utils.web import WebPhase


def _make_response(status_code: int, json_data: dict | None = None, content: bytes = b"") -> MagicMock:
    """
    Construit une fausse reponse HTTP pour les tests.

    :param status_code: code HTTP a renvoyer
    :param json_data: corps JSON a renvoyer (None si pas de JSON valide)
    :param content: corps brut a renvoyer
    :return: objet simulant une reponse requests
    """
    response = MagicMock()
    response.status_code = status_code
    response.content = content
    if json_data is None:
        response.json.side_effect = ValueError("pas de JSON")
    else:
        response.json.return_value = json_data
    return response


def test_given_valid_candidate_when_run_then_returns_flag_host_port_key() -> None:
    # Given
    web_phase = WebPhase("http://127.0.0.1:8080")
    success_response = _make_response(
        200,
        json_data={"flag1": "ESGI{test}", "host": "127.0.0.1", "port": "9090", "key": "ab"},
    )

    with (
        patch.object(web_phase, "_visit_candidate", return_value=True),
        patch.object(web_phase, "_get_captcha_image", return_value=b"captcha-bytes"),
        patch.object(web_phase.captcha_solver, "solve", return_value="AB12"),
        patch.object(web_phase, "_submit_captcha", return_value=success_response),
        patch("tp3.utils.web.Fuzzer") as fuzzer_class,
    ):
        fuzzer_class.return_value.find_hidden_pages.return_value = ["internal-panel"]

        # When
        flag, host, port, key = web_phase.run()

    # Then
    assert flag == "ESGI{test}"
    assert host == "127.0.0.1"
    assert port == 9090
    assert key == bytes.fromhex("ab")


def test_given_no_candidate_found_when_run_then_raises_runtime_error() -> None:
    # Given
    web_phase = WebPhase("http://127.0.0.1:8080")

    # When / Then
    with (
        patch("tp3.utils.web.Fuzzer") as fuzzer_class,
        pytest.raises(RuntimeError),
    ):
        fuzzer_class.return_value.find_hidden_pages.return_value = []
        web_phase.run()