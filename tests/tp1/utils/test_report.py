import json
from unittest.mock import MagicMock

from src.tp1.utils.report import Report


def _fake_capture(attacks: list | None = None, flag: str = "") -> MagicMock:
    capture = MagicMock()
    capture.pcap_file = "test.pcap"
    capture.interface = ""
    capture.packets = [None] * 10
    capture.sort_network_protocols.return_value = [("Ethernet", 10), ("IP", 8), ("TCP", 5)]
    if attacks is None:
        attacks = []
    capture.attacks = attacks
    capture.flag = flag
    return capture


def _scan_attack() -> dict:
    return {
        "type": "port_scan",
        "attacker": "10.0.0.5",
        "protocol": "TCP",
        "details": "40 ports differents sondes",
        "block_rule": "iptables -A INPUT -s 10.0.0.5 -j DROP",
    }


def test_report_init():
    # Given
    capture = MagicMock()
    filename = "test.pdf"
    summary = "Test summary"

    # When
    report = Report(capture, filename, summary)

    # Then
    assert report.capture == capture
    assert report.filename == filename
    assert report.title == "Rapport IDS/IPS - TP1"
    assert report.summary == summary
    assert report.array == []
    assert report.graph == ""


def test_concat_report():
    # Given
    report = Report(MagicMock(), "test.pdf", "Test summary")
    report.title = "Test Title"
    report.array = [["TCP", 5, "50.0 %"]]

    # When
    result = report.concat_report()

    # Then
    assert result == "Test Title\nTest summary\nTCP: 5 paquets (50.0 %)\n"


def test_generate_graph():
    # Given
    report = Report(_fake_capture(), "test.pdf", "Test summary")

    # When
    report.generate("graph")

    # Then
    assert report.graph.startswith("<?xml") or report.graph.startswith("<svg")
    assert "Ethernet" in report.graph
    assert "TCP" in report.graph


def test_generate_array():
    # Given
    report = Report(_fake_capture(), "test.pdf", "Test summary")

    # When
    report.generate("array")

    # Then
    assert report.array == [["Ethernet", 10, "100.0 %"], ["IP", 8, "80.0 %"], ["TCP", 5, "50.0 %"]]


def test_generate_invalid_param():
    # Given
    report = Report(_fake_capture(), "test.pdf", "Test summary")

    # When
    report.generate("invalid")

    # Then
    assert report.graph == ""
    assert report.array == []


def test_given_attack_when_save_then_pdf_and_svg_are_created(tmp_path):
    # Given
    pdf_file = tmp_path / "report.pdf"
    report = Report(_fake_capture([_scan_attack()], "ESGI{test}"), str(pdf_file), "Test summary")
    report.generate("graph")
    report.generate("array")

    # When
    report.save(str(pdf_file))

    # Then
    assert pdf_file.read_bytes().startswith(b"%PDF")
    assert (tmp_path / "report_graph.svg").exists()


def test_given_no_attack_when_save_then_pdf_is_created(tmp_path):
    # Given
    pdf_file = tmp_path / "sub" / "report.pdf"
    report = Report(_fake_capture(), str(pdf_file), "Test summary")

    # When
    report.save(str(pdf_file))

    # Then
    assert pdf_file.read_bytes().startswith(b"%PDF")


def test_given_analysed_capture_when_save_json_then_json_has_expected_format(tmp_path):
    # Given
    json_file = tmp_path / "report.json"
    report = Report(_fake_capture([_scan_attack()], "ESGI{test}"), "report.pdf", "Test summary")

    # When
    report.save_json(str(json_file))

    # Then
    data = json.loads(json_file.read_text(encoding="utf-8"))
    assert data == {
        "protocols": {"Ethernet": 10, "IP": 8, "TCP": 5},
        "attacks": [{"type": "port_scan", "attacker": "10.0.0.5"}],
        "flag": "ESGI{test}",
    }
