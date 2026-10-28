"""
Tests pour le point d'entree du TP3 (parsing des arguments et orchestration).
"""

from unittest.mock import patch

from tp3.main import _parse_arguments, main


def test_given_target_argument_when_parse_arguments_then_target_is_set() -> None:
    # Given
    arguments = ["--target", "http://127.0.0.1:8080"]

    # When
    parsed = _parse_arguments(arguments)

    # Then
    assert parsed.target == "http://127.0.0.1:8080"


def test_given_both_phases_succeed_when_main_then_returns_zero() -> None:
    # Given
    arguments = ["--target", "http://127.0.0.1:8080"]

    with (
        patch("tp3.main.WebPhase") as web_phase_class,
        patch("tp3.main.NetworkPhase") as network_phase_class,
    ):
        web_phase_class.return_value.run.return_value = ("ESGI{flag1}", "127.0.0.1", 9090, b"key")
        network_phase_class.return_value.run.return_value = "ESGI{final}"

        # When
        exit_code = main(arguments)

    # Then
    assert exit_code == 0


def test_given_web_phase_fails_when_main_then_returns_one() -> None:
    # Given
    arguments = ["--target", "http://127.0.0.1:8080"]

    with patch("tp3.main.WebPhase") as web_phase_class:
        web_phase_class.return_value.run.side_effect = RuntimeError("echec web")

        # When
        exit_code = main(arguments)

    # Then
    assert exit_code == 1


def test_given_network_phase_fails_when_main_then_returns_one() -> None:
    # Given
    arguments = ["--target", "http://127.0.0.1:8080"]

    with (
        patch("tp3.main.WebPhase") as web_phase_class,
        patch("tp3.main.NetworkPhase") as network_phase_class,
    ):
        web_phase_class.return_value.run.return_value = ("ESGI{flag1}", "127.0.0.1", 9090, b"key")
        network_phase_class.return_value.run.side_effect = RuntimeError("echec reseau")

        # When
        exit_code = main(arguments)

    # Then
    assert exit_code == 1