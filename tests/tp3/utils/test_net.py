"""
Tests pour la phase reseau (NetworkPhase).
"""

import base64
from unittest.mock import MagicMock, patch

import pytest

from tp3.utils.net import NetworkPhase


def _xor(data: bytes, key: bytes) -> bytes:
    """
    Applique un XOR entre des donnees et une cle repetee.

    :param data: donnees a chiffrer/dechiffrer
    :param key: cle XOR
    :return: donnees apres XOR
    """
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))


def _make_socket(lines: list[bytes]) -> MagicMock:
    """
    Construit une fausse socket renvoyant des lignes predefinies.

    :param lines: lignes a renvoyer successivement (deja terminees par un saut de ligne)
    :return: objet simulant une socket connectee
    """
    connection = MagicMock()
    connection.__enter__.return_value = connection
    connection.recv.side_effect = [*lines, b""]
    return connection


def test_given_server_sends_flag_when_run_then_returns_decoded_flag() -> None:
    # Given
    key = b"key"
    token = base64.b64encode(_xor(b"ping", key))
    socket_mock = _make_socket([b"welcome\n", token + b"\n", b"OK ESGI{final}\n"])
    network_phase = NetworkPhase("127.0.0.1", 9090, key)

    with patch("tp3.utils.net.socket.create_connection", return_value=socket_mock):
        # When
        flag = network_phase.run()

    # Then
    assert flag == "ESGI{final}"


def test_given_server_sends_wrong_when_run_then_raises_runtime_error() -> None:
    # Given
    key = b"key"
    socket_mock = _make_socket([b"welcome\n", b"WRONG\n"])
    network_phase = NetworkPhase("127.0.0.1", 9090, key)

    # When / Then
    with (
        patch("tp3.utils.net.socket.create_connection", return_value=socket_mock),
        pytest.raises(RuntimeError),
    ):
        network_phase.run()