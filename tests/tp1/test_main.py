import json

from scapy.all import ARP, IP, TCP, Ether, Raw, wrpcap

from src.tp1.main import _parse_arguments, main


def test_given_pcap_and_out_when_parse_arguments_then_options_are_read():
    # Given
    arguments = ["--pcap", "capture.pcap", "--out", "result.json"]

    # When
    args = _parse_arguments(arguments)

    # Then
    assert args.pcap == "capture.pcap"
    assert args.out == "result.json"
    assert args.iface is None
    assert args.pdf is None


def test_given_no_option_when_parse_arguments_then_default_out_is_report_json():
    # When
    args = _parse_arguments([])

    # Then
    assert args.out == "report.json"


def test_given_pcap_with_attacks_when_main_then_json_and_pdf_are_written(tmp_path):
    # Given
    pcap_file = tmp_path / "capture.pcap"
    json_file = tmp_path / "report.json"
    packets = [Ether() / ARP()]
    for port in range(1, 30):
        packets.append(Ether() / IP(src="10.0.0.5", dst="10.0.0.20") / TCP(dport=port, flags="S"))
    request = b"GET /search?q=1+UNION+SELECT+1&t=ESGI{main_test} HTTP/1.1\r\n\r\n"
    packets.append(Ether() / IP(src="10.0.0.9") / TCP(dport=80, flags="PA") / Raw(load=request))
    wrpcap(str(pcap_file), packets)

    # When
    exit_code = main(["--pcap", str(pcap_file), "--out", str(json_file)])

    # Then
    assert exit_code == 0
    data = json.loads(json_file.read_text(encoding="utf-8"))
    assert data["protocols"]["TCP"] == 30
    assert data["protocols"]["ARP"] == 1
    assert {"type": "port_scan", "attacker": "10.0.0.5"} in data["attacks"]
    assert {"type": "sql_injection", "attacker": "10.0.0.9"} in data["attacks"]
    assert data["flag"] == "ESGI{main_test}"
    assert (tmp_path / "report.pdf").exists()


def test_given_missing_pcap_when_main_then_return_error_code(tmp_path):
    # Given
    missing_file = tmp_path / "missing.pcap"

    # When
    exit_code = main(["--pcap", str(missing_file), "--out", str(tmp_path / "report.json")])

    # Then
    assert exit_code == 1
