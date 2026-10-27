from unittest.mock import MagicMock, patch

from src.tp1.utils.lib import (
    build_block_rule,
    choose_interface,
    hello_world,
    is_http_payload,
    is_http_request,
    is_mac_address,
)


def _fake_interface(name: str) -> MagicMock:
    interface = MagicMock()
    interface.name = name
    interface.description = f"description {name}"
    return interface


def test_when_hello_world_then_return_hello_world():
    # Given
    string = "hello world"

    # When
    result = hello_world()

    # Then
    assert result == string


def test_given_interface_argument_when_choose_interface_then_return_it():
    # Given
    interface = "eth0"

    # When
    result = choose_interface(interface)

    # Then
    assert result == "eth0"


def test_given_user_choice_when_choose_interface_then_return_chosen_interface():
    # Given
    interfaces = [_fake_interface("eth0"), _fake_interface("wlan0")]

    # When
    with (
        patch("scapy.all.get_working_ifaces", return_value=interfaces),
        patch("builtins.input", return_value="1"),
    ):
        result = choose_interface()

    # Then
    assert result == "wlan0"


def test_given_empty_answer_when_choose_interface_then_return_default_interface():
    # Given
    interfaces = [_fake_interface("eth0"), _fake_interface("wlan0")]

    # When
    with (
        patch("scapy.all.get_working_ifaces", return_value=interfaces),
        patch("scapy.all.conf") as mock_conf,
        patch("builtins.input", return_value=""),
    ):
        mock_conf.iface = "eth0"
        result = choose_interface()

    # Then
    assert result == "eth0"


def test_given_invalid_answer_when_choose_interface_then_return_default_interface():
    # Given
    interfaces = [_fake_interface("eth0")]

    # When
    with (
        patch("scapy.all.get_working_ifaces", return_value=interfaces),
        patch("scapy.all.conf") as mock_conf,
        patch("builtins.input", return_value="42"),
    ):
        mock_conf.iface = "eth0"
        result = choose_interface()

    # Then
    assert result == "eth0"


def test_given_http_request_when_is_http_request_then_return_true():
    # Given
    payload = b"GET /index.html HTTP/1.1\r\nHost: intranet\r\n\r\n"

    # When
    result = is_http_request(payload)

    # Then
    assert result is True


def test_given_binary_data_when_is_http_request_then_return_false():
    # Given
    payload = b"\x16\x03\x01\x02\x00"

    # When
    result = is_http_request(payload)

    # Then
    assert result is False


def test_given_http_response_when_is_http_payload_then_return_true():
    # Given
    payload = b"HTTP/1.1 200 OK\r\n\r\n"

    # When
    result = is_http_payload(payload)

    # Then
    assert result is True


def test_given_mac_and_ip_when_is_mac_address_then_only_mac_is_true():
    # Given
    mac = "aa:bb:cc:dd:ee:ff"
    ip = "10.0.0.5"

    # When
    mac_result = is_mac_address(mac)
    ip_result = is_mac_address(ip)

    # Then
    assert mac_result is True
    assert ip_result is False


def test_given_ip_when_build_block_rule_then_return_iptables_and_netsh_rules():
    # Given
    attacker = "10.0.0.5"

    # When
    rule = build_block_rule(attacker)

    # Then
    assert "iptables -A INPUT -s 10.0.0.5 -j DROP" in rule
    assert "remoteip=10.0.0.5" in rule


def test_given_mac_when_build_block_rule_then_return_arptables_rule():
    # Given
    attacker = "aa:bb:cc:dd:ee:ff"

    # When
    rule = build_block_rule(attacker)

    # Then
    assert "arptables -A INPUT --source-mac aa:bb:cc:dd:ee:ff -j DROP" in rule
