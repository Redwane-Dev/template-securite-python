"""
Tests pour le parsing des arguments du TP3.
"""

from tp3.main import _parse_arguments


def test_given_target_argument_when_parse_arguments_then_target_is_set() -> None:
    # Given
    arguments = ["--target", "http://127.0.0.1:8080"]

    # When
    parsed = _parse_arguments(arguments)

    # Then
    assert parsed.target == "http://127.0.0.1:8080"