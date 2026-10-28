"""
Tests pour l'orchestration de la phase web (WebPhase).
"""

from unittest.mock import MagicMock, patch

import pytest
import requests

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

    with (
        patch("tp3.utils.web.Fuzzer") as fuzzer_class,
        pytest.raises(RuntimeError),
    ):
        fuzzer_class.return_value.find_hidden_pages.return_value = []
        web_phase.run()


def test_given_reachable_page_when_visit_candidate_then_returns_true() -> None:
    # Given
    web_phase = WebPhase("http://127.0.0.1:8080")

    with patch.object(web_phase.session, "get", return_value=_make_response(200)):
        # When
        result = web_phase._visit_candidate("http://127.0.0.1:8080/internal-panel")

    # Then
    assert result is True


def test_given_network_error_when_visit_candidate_then_returns_false() -> None:
    # Given
    web_phase = WebPhase("http://127.0.0.1:8080")

    with patch.object(web_phase.session, "get", side_effect=requests.RequestException("boom")):
        # When
        result = web_phase._visit_candidate("http://127.0.0.1:8080/internal-panel")

    # Then
    assert result is False


def test_given_captcha_endpoint_ok_when_get_captcha_image_then_returns_bytes() -> None:
    # Given
    web_phase = WebPhase("http://127.0.0.1:8080")
    response = _make_response(200, content=b"captcha-bytes")

    with patch.object(web_phase.session, "get", return_value=response):
        # When
        result = web_phase._get_captcha_image()

    # Then
    assert result == b"captcha-bytes"


def test_given_captcha_endpoint_fails_when_get_captcha_image_then_returns_none() -> None:
    # Given
    web_phase = WebPhase("http://127.0.0.1:8080")
    response = _make_response(404)

    with patch.object(web_phase.session, "get", return_value=response):
        # When
        result = web_phase._get_captcha_image()

    # Then
    assert result is None


def test_given_reachable_page_when_submit_captcha_then_returns_response() -> None:
    # Given
    web_phase = WebPhase("http://127.0.0.1:8080")
    response = _make_response(200)

    with patch.object(web_phase.session, "post", return_value=response):
        # When
        result = web_phase._submit_captcha("http://127.0.0.1:8080/internal-panel", "AB12")

    # Then
    assert result is response


def test_given_network_error_when_submit_captcha_then_returns_none() -> None:
    # Given
    web_phase = WebPhase("http://127.0.0.1:8080")

    with patch.object(web_phase.session, "post", side_effect=requests.RequestException("boom")):
        # When
        result = web_phase._submit_captcha("http://127.0.0.1:8080/internal-panel", "AB12")

    # Then
    assert result is None


def test_given_complete_json_when_extract_breach_info_then_returns_tuple() -> None:
    # Given
    web_phase = WebPhase("http://127.0.0.1:8080")
    response = _make_response(
        200,
        json_data={"flag1": "ESGI{test}", "host": "127.0.0.1", "port": "9090", "key": "ab"},
    )

    # When
    result = web_phase._extract_breach_info(response)

    # Then
    assert result == ("ESGI{test}", "127.0.0.1", 9090, bytes.fromhex("ab"))


def test_given_missing_field_when_extract_breach_info_then_returns_none() -> None:
    # Given
    web_phase = WebPhase("http://127.0.0.1:8080")
    response = _make_response(200, json_data={"flag1": "ESGI{test}", "host": "127.0.0.1"})

    # When
    result = web_phase._extract_breach_info(response)

    # Then
    assert result is None


def test_given_non_200_status_when_extract_breach_info_then_returns_none() -> None:
    # Given
    web_phase = WebPhase("http://127.0.0.1:8080")
    response = _make_response(403, json_data={"flag1": "x", "host": "h", "port": "1", "key": "ab"})

    # When
    result = web_phase._extract_breach_info(response)

    # Then
    assert result is None


def test_given_successful_captcha_when_try_candidate_then_returns_breach_info() -> None:
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
    ):
        # When
        result = web_phase._try_candidate("http://127.0.0.1:8080/internal-panel")

    # Then
    assert result == ("ESGI{test}", "127.0.0.1", 9090, bytes.fromhex("ab"))


def test_given_page_unreachable_when_try_candidate_then_returns_none() -> None:
    # Given
    web_phase = WebPhase("http://127.0.0.1:8080")

    with patch.object(web_phase, "_visit_candidate", return_value=False):
        # When
        result = web_phase._try_candidate("http://127.0.0.1:8080/unknown")

    # Then
    assert result is None