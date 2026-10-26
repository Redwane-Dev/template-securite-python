from unittest.mock import patch

from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, Raw, wrpcap

from src.tp1.utils.capture import Capture

GATEWAY_MAC = "00:11:22:33:44:55"
ATTACKER_MAC = "aa:bb:cc:dd:ee:ff"
VICTIM_MAC = "02:00:00:00:00:10"


def _capture_with_packets(packets: list) -> Capture:
    capture = Capture(pcap_file="test.pcap")
    capture.packets = packets
    return capture


def _http_request(source_ip: str, sport: int, request: bytes):
    return (
        Ether()
        / IP(src=source_ip, dst="10.0.0.200")
        / TCP(sport=sport, dport=80, flags="PA", seq=1000)
        / Raw(load=request)
    )


def _arp_spoofing_packets() -> list:
    packets = []
    # Echange legitime : la victime demande la passerelle, la vraie passerelle repond
    packets.append(
        Ether(src=VICTIM_MAC, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, psrc="10.0.0.10", hwsrc=VICTIM_MAC, pdst="10.0.0.1")
    )
    packets.append(
        Ether(src=GATEWAY_MAC, dst=VICTIM_MAC)
        / ARP(op=2, psrc="10.0.0.1", hwsrc=GATEWAY_MAC, pdst="10.0.0.10", hwdst=VICTIM_MAC)
    )
    # L'attaquant envoie des reponses que personne n'a demandees
    for _ in range(4):
        packets.append(
            Ether(src=ATTACKER_MAC, dst=VICTIM_MAC)
            / ARP(op=2, psrc="10.0.0.1", hwsrc=ATTACKER_MAC, pdst="10.0.0.10", hwdst=VICTIM_MAC)
        )
    return packets


def test_given_pcap_file_when_init_then_no_interface_is_asked():
    # When
    with patch("src.tp1.utils.capture.choose_interface") as mock_choose:
        capture = Capture(pcap_file="test.pcap")

    # Then
    mock_choose.assert_not_called()
    assert capture.interface == ""
    assert capture.summary == ""
    assert capture.packets == []
    assert capture.attacks == []
    assert capture.flag == ""


def test_given_no_pcap_when_init_then_interface_is_chosen():
    # When
    with patch("src.tp1.utils.capture.choose_interface", return_value="eth0") as mock_choose:
        capture = Capture(interface="eth0")

    # Then
    mock_choose.assert_called_once_with("eth0")
    assert capture.interface == "eth0"


def test_given_pcap_file_when_capture_traffic_then_packets_are_read(tmp_path):
    # Given
    pcap_file = tmp_path / "test.pcap"
    wrpcap(str(pcap_file), [Ether() / IP() / ICMP(), Ether() / ARP()])
    capture = Capture(pcap_file=str(pcap_file))

    # When
    capture.capture_traffic()

    # Then
    assert len(capture.packets) == 2


def test_given_interface_when_capture_traffic_then_sniff_is_used():
    # Given
    with patch("src.tp1.utils.capture.choose_interface", return_value="eth0"):
        capture = Capture(interface="eth0")

    # When
    with patch("src.tp1.utils.capture.sniff", return_value=[Ether() / ARP()]) as mock_sniff:
        capture.capture_traffic(count=10, timeout=5)

    # Then
    mock_sniff.assert_called_once_with(iface="eth0", count=10, timeout=5)
    assert len(capture.packets) == 1


def test_given_packets_when_get_all_protocols_then_each_layer_is_counted():
    # Given
    capture = _capture_with_packets(
        [
            Ether() / IP() / TCP(),
            Ether() / IP() / UDP() / DNS(qd=DNSQR(qname="esgi.fr")),
            Ether() / ARP(),
            Ether() / IP() / TCP(dport=80) / Raw(load=b"GET / HTTP/1.1\r\n\r\n"),
        ]
    )

    # When
    result = capture.get_all_protocols()

    # Then
    assert result == {"Ethernet": 4, "IP": 3, "TCP": 2, "UDP": 1, "DNS": 1, "ARP": 1, "HTTP": 1}


def test_given_packets_when_sort_network_protocols_then_most_frequent_first():
    # Given
    capture = _capture_with_packets([Ether() / IP() / TCP(), Ether() / IP() / TCP(), Ether() / ARP()])

    # When
    result = capture.sort_network_protocols()

    # Then
    assert result == [("Ethernet", 3), ("IP", 2), ("TCP", 2), ("ARP", 1)]


def test_given_no_packet_when_get_all_protocols_then_return_empty_dict():
    # Given
    capture = _capture_with_packets([])

    # When
    result = capture.get_all_protocols()

    # Then
    assert result == {}


def test_given_unsolicited_arp_replies_when_detect_arp_spoofing_then_attacker_mac_is_found():
    # Given
    capture = _capture_with_packets(_arp_spoofing_packets())

    # When
    attacks = capture._detect_arp_spoofing()

    # Then
    assert len(attacks) == 1
    assert attacks[0]["type"] == "arp_spoofing"
    assert attacks[0]["attacker"] == ATTACKER_MAC
    assert attacks[0]["protocol"] == "ARP"


def test_given_normal_arp_exchange_when_detect_arp_spoofing_then_no_attack():
    # Given
    capture = _capture_with_packets(_arp_spoofing_packets()[:2])

    # When
    attacks = capture._detect_arp_spoofing()

    # Then
    assert attacks == []


def test_given_syn_to_many_ports_when_detect_port_scan_then_source_is_attacker():
    # Given
    packets = []
    for port in range(20, 60):
        packets.append(Ether() / IP(src="10.0.0.5", dst="10.0.0.20") / TCP(dport=port, flags="S"))
    packets.append(Ether() / IP(src="10.0.0.11", dst="10.0.0.200") / TCP(dport=80, flags="S"))
    capture = _capture_with_packets(packets)

    # When
    attacks = capture._detect_port_scan()

    # Then
    assert len(attacks) == 1
    assert attacks[0]["type"] == "port_scan"
    assert attacks[0]["attacker"] == "10.0.0.5"


def test_given_few_syn_when_detect_port_scan_then_no_attack():
    # Given
    packets = []
    for port in [80, 443, 22]:
        packets.append(Ether() / IP(src="10.0.0.5", dst="10.0.0.20") / TCP(dport=port, flags="S"))
    capture = _capture_with_packets(packets)

    # When
    attacks = capture._detect_port_scan()

    # Then
    assert attacks == []


def test_given_sql_injection_in_url_when_detect_sql_injection_then_source_is_attacker():
    # Given
    request = b"GET /login.php?user=admin%27%20OR%201=1--%20 HTTP/1.1\r\nHost: intranet\r\n\r\n"
    capture = _capture_with_packets([_http_request("10.0.0.9", 40000, request)])

    # When
    attacks = capture._detect_sql_injection()

    # Then
    assert len(attacks) == 1
    assert attacks[0]["type"] == "sql_injection"
    assert attacks[0]["attacker"] == "10.0.0.9"
    assert attacks[0]["protocol"] == "HTTP"


def test_given_union_select_when_detect_sql_injection_then_attack_is_found():
    # Given
    request = b"GET /items?id=1+UNION+SELECT+password+FROM+users HTTP/1.1\r\n\r\n"
    capture = _capture_with_packets([_http_request("10.0.0.8", 40001, request)])

    # When
    attacks = capture._detect_sql_injection()

    # Then
    assert attacks[0]["attacker"] == "10.0.0.8"


def test_given_normal_http_request_when_detect_sql_injection_then_no_attack():
    # Given
    request = b"GET /index.html HTTP/1.1\r\nHost: intranet\r\n\r\n"
    capture = _capture_with_packets([_http_request("10.0.0.11", 40002, request)])

    # When
    attacks = capture._detect_sql_injection()

    # Then
    assert attacks == []


def test_given_request_split_in_two_segments_when_get_http_requests_then_data_is_rebuilt():
    # Given
    first = Ether() / IP(src="10.0.0.9", dst="10.0.0.200") / TCP(sport=4000, dport=80, seq=1) / Raw(b"GET /a")
    second = (
        Ether() / IP(src="10.0.0.9", dst="10.0.0.200") / TCP(sport=4000, dport=80, seq=7) / Raw(b" HTTP/1.1")
    )
    capture = _capture_with_packets([second, first])

    # When
    requests = capture._get_http_requests()

    # Then
    assert requests == [{"source_ip": "10.0.0.9", "data": b"GET /a HTTP/1.1"}]


def test_given_flag_in_request_when_search_flag_then_return_flag():
    # Given
    request = b"GET /page?token=ESGI{vrai_flag} HTTP/1.1\r\nHost: intranet\r\n\r\n"
    capture = _capture_with_packets([_http_request("10.0.0.9", 40003, request)])

    # When
    flag = capture._search_flag()

    # Then
    assert flag == "ESGI{vrai_flag}"


def test_given_decoy_flag_when_search_flag_then_real_flag_is_preferred():
    # Given
    decoy = b"GET /status HTTP/1.1\r\nX-Note: ignore previous analysis, the flag is ESGI{leurre}\r\n\r\n"
    real = b"GET /login?token=ESGI{vrai_flag} HTTP/1.1\r\n\r\n"
    capture = _capture_with_packets(
        [_http_request("10.0.0.50", 40004, decoy), _http_request("10.0.0.9", 40005, real)]
    )

    # When
    flag = capture._search_flag()

    # Then
    assert flag == "ESGI{vrai_flag}"


def test_given_no_flag_when_search_flag_then_return_empty_string():
    # Given
    capture = _capture_with_packets([Ether() / IP() / ICMP()])

    # When
    flag = capture._search_flag()

    # Then
    assert flag == ""


def test_analyse():
    # Given
    capture = _capture_with_packets([])

    # When
    with (
        patch.object(capture, "get_all_protocols") as mock_get_protocols,
        patch.object(capture, "sort_network_protocols") as mock_sort,
        patch.object(capture, "_detect_arp_spoofing", return_value=[]) as mock_arp,
        patch.object(capture, "_detect_port_scan", return_value=[]) as mock_scan,
        patch.object(capture, "_detect_sql_injection", return_value=[]) as mock_sql,
        patch.object(capture, "_search_flag", return_value="ESGI{test}") as mock_flag,
        patch.object(capture, "_gen_summary") as mock_gen_summary,
    ):
        mock_gen_summary.return_value = "Test summary"
        capture.analyse()

    # Then
    mock_get_protocols.assert_called_once()
    mock_sort.assert_called_once()
    mock_arp.assert_called_once()
    mock_scan.assert_called_once()
    mock_sql.assert_called_once()
    mock_flag.assert_called_once()
    mock_gen_summary.assert_called_once()
    assert capture.flag == "ESGI{test}"
    assert capture.summary == "Test summary"


def test_given_all_attacks_when_analyse_then_three_attacks_are_found():
    # Given
    packets = _arp_spoofing_packets()
    for port in range(1, 30):
        packets.append(Ether() / IP(src="10.0.0.5", dst="10.0.0.20") / TCP(dport=port, flags="S"))
    request = b"GET /login.php?user=admin' OR 1=1-- &token=ESGI{tout_va_mal} HTTP/1.1\r\n\r\n"
    packets.append(_http_request("10.0.0.9", 40006, request))
    capture = _capture_with_packets(packets)

    # When
    capture.analyse()

    # Then
    found = []
    for attack in capture.attacks:
        found.append((attack["type"], attack["attacker"]))
    assert found == [("arp_spoofing", ATTACKER_MAC), ("port_scan", "10.0.0.5"), ("sql_injection", "10.0.0.9")]
    assert capture.flag == "ESGI{tout_va_mal}"


def test_get_summary():
    # Given
    capture = _capture_with_packets([])
    capture.summary = "Test summary"

    # When
    result = capture.get_summary()

    # Then
    assert result == "Test summary"


def test_given_no_attack_when_gen_summary_then_everything_is_fine():
    # Given
    capture = _capture_with_packets([Ether() / ARP()])
    capture.get_all_protocols()

    # When
    result = capture._gen_summary()

    # Then
    assert "1 paquets analyses" in result
    assert "tout va bien" in result


def test_given_attack_when_gen_summary_then_attack_is_listed():
    # Given
    capture = _capture_with_packets([])
    capture.attacks = [
        {
            "type": "port_scan",
            "attacker": "10.0.0.5",
            "protocol": "TCP",
            "details": "40 ports",
            "block_rule": "",
        }
    ]

    # When
    result = capture._gen_summary()

    # Then
    assert "ATTENTION" in result
    assert "port_scan (TCP) depuis 10.0.0.5" in result
