"""
Tests pour la phase reseau (NetworkPhase).
"""

import base64
import binascii
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

    with (
        patch("tp3.utils.net.socket.create_connection", return_value=socket_mock),
        pytest.raises(RuntimeError),
    ):
        network_phase.run()


def test_given_valid_base64_token_when_decode_token_then_returns_xor_result() -> None:
    # Given
    key = b"key"
    plaintext = b"ping"
    token = base64.b64encode(_xor(plaintext, key))
    network_phase = NetworkPhase("127.0.0.1", 9090, key)

    # When
    result = network_phase._decode_token(token)

    # Then
    assert result == plaintext


def test_given_invalid_base64_when_decode_token_then_raises_binascii_error() -> None:
    # Given
    network_phase = NetworkPhase("127.0.0.1", 9090, b"key")

    # When / Then
    with pytest.raises(binascii.Error):
        network_phase._decode_token(b"not-valid-base64!!")


def test_given_complete_line_when_read_line_then_returns_line_and_remaining_buffer() -> None:
    # Given
    network_phase = NetworkPhase("127.0.0.1", 9090, b"key")
    connection = MagicMock()
    connection.recv.return_value = b"hello\nworld"

    # When
    line, buffer = network_phase._read_line(connection, b"")

    # Then
    assert line == b"hello"
    assert buffer == b"world"


def test_given_connection_closed_when_read_line_then_returns_none() -> None:
    # Given
    network_phase = NetworkPhase("127.0.0.1", 9090, b"key")
    connection = MagicMock()
    connection.recv.return_value = b""

    # When
    line, buffer = network_phase._read_line(connection, b"")

    # Then
    assert line is None
    assert buffer == b""