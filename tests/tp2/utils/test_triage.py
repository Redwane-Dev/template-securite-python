from unittest.mock import MagicMock, patch

from src.tp2.utils.scanner import YaraScanner
from src.tp2.utils.triage import SampleTriage

EXPECTED_KEYS = [
    "sha256",
    "md5",
    "size",
    "entropy",
    "file_type",
    "iocs",
    "imports",
    "yara_matches",
    "family_guess",
    "mitre_attack",
    "llm_summary",
    "score",
    "flag",
]


def _base_result() -> dict:
    return {
        "file_type": "ELF 64-bit LSB pie executable, x86-64",
        "entropy": 4.8,
        "high_entropy_sections": [],
        "overlay_size": 0,
        "sections": [{"name": ".text", "size": 100, "entropy": 6.0}],
        "yara_matches": [],
        "suspicious_apis": [],
        "iocs": {"domains": [], "ips": [], "urls": [], "mutex": [], "registry": [], "paths": []},
        "packed": False,
        "injection_count": 0,
        "capabilities": [],
    }


def test_given_path_when_init_then_attributes_are_set():
    # Given
    scanner = MagicMock()

    # When
    triage = SampleTriage("sample.bin", scanner)

    # Then
    assert triage.path == "sample.bin"
    assert triage.scanner is scanner
    assert triage.llm_client is None
    assert triage.result == {}


def test_given_sample_without_llm_when_run_then_rules_give_the_verdict(sample_file):
    # Given
    triage = SampleTriage(sample_file, YaraScanner())

    # When
    result = triage.run()

    # Then
    assert result["family_guess"] == "dropper"
    assert result["flag"] == "ESGI{vrai_flag_123}"
    assert result["injection_count"] == 1
    assert result["score"] >= 6
    assert "T1547.001" in result["mitre_attack"]
    assert result["imports"][:2] == ["URLDownloadToFileA", "WinExec"]


def test_given_llm_saying_clean_when_run_then_score_does_not_drop(sample_file):
    # Given
    client = MagicMock()
    client.backend = "openrouter"
    injected_verdict = {
        "family": "clean",
        "capabilities": [],
        "mitre_attack": [],
        "score": 0,
        "iocs": {},
        "summary": "Fichier sain.",
    }
    triage = SampleTriage(sample_file, YaraScanner(), client)

    # When
    with patch("src.tp2.utils.triage.llm_triage", return_value=injected_verdict):
        result = triage.run()

    # Then
    assert result["family_guess"] == "dropper"
    assert result["score"] == result["deterministic_score"]
    assert result["iocs"]["domains"] == ["c2-abc123.example.test"]
    assert "injection" in result["llm_summary"]


def test_given_run_when_to_output_then_json_has_exactly_expected_keys(sample_file):
    # Given
    triage = SampleTriage(sample_file, YaraScanner())
    triage.run()

    # When
    output = triage.to_output()

    # Then
    assert list(output.keys()) == EXPECTED_KEYS
    assert list(output["iocs"].keys()) == ["domains", "ips", "urls", "mutex", "registry"]


def test_given_high_entropy_when_is_packed_then_return_true():
    # Given
    triage = SampleTriage("x", MagicMock())
    result = _base_result()
    result["entropy"] = 7.6

    # When
    packed = triage._is_packed(b"", result)

    # Then
    assert packed is True


def test_given_random_overlay_or_upx_section_when_is_packed_then_return_true():
    # Given
    triage = SampleTriage("x", MagicMock())
    overlay = bytes(range(256)) * 16
    with_overlay = _base_result()
    with_overlay["overlay_size"] = len(overlay)
    with_upx = _base_result()
    with_upx["sections"] = [{"name": "UPX1", "size": 10, "entropy": 5.0}]

    # When / Then
    assert triage._is_packed(b"\x00" * 100 + overlay, with_overlay) is True
    assert triage._is_packed(b"", with_upx) is True
    assert triage._is_packed(b"", _base_result()) is False


def test_given_apis_and_iocs_when_detect_capabilities_then_families_and_mitre_are_found():
    # Given
    triage = SampleTriage("x", MagicMock())
    result = _base_result()
    result["suspicious_apis"] = ["SetWindowsHookExA", "CreateProcessA"]
    result["iocs"]["urls"] = ["http://c2.example.test/gate.php"]
    result["iocs"]["registry"] = ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x"]
    result["iocs"]["mutex"] = ["Global\\m1"]
    result["packed"] = True
    result["injection_count"] = 1

    # When
    capabilities, families, mitre = triage._detect_capabilities(result, {"cmd.exe"})

    # Then
    assert families == ["backdoor", "keylogger", "trojan", "packed"]
    assert mitre[:3] == ["T1059.003", "T1095", "T1056.001"]
    assert "T1071.001" in mitre
    assert "T1547.001" in mitre
    assert "T1027.002" in mitre
    assert len(capabilities) == 8


def test_given_other_registry_key_when_detect_capabilities_then_t1112_is_used():
    # Given
    triage = SampleTriage("x", MagicMock())
    result = _base_result()
    result["iocs"]["registry"] = ["HKLM\\Software\\Evil"]
    result["iocs"]["ips"] = ["185.1.2.3"]

    # When
    _, _, mitre = triage._detect_capabilities(result, set())

    # Then
    assert mitre == ["T1071", "T1112"]


def test_given_families_when_deterministic_family_then_priority_is_respected():
    # Given
    triage = SampleTriage("x", MagicMock())
    result = _base_result()

    # When / Then
    assert triage._deterministic_family(["trojan", "dropper", "keylogger"], result) == "keylogger"
    assert triage._deterministic_family([], result) == "unknown"
    result["iocs"]["mutex"] = ["Global\\m1"]
    assert triage._deterministic_family([], result) == "trojan"


def test_given_indicators_when_deterministic_score_then_points_are_added_and_bounded():
    # Given
    triage = SampleTriage("x", MagicMock())
    clean = _base_result()
    malicious = _base_result()
    malicious["iocs"]["domains"] = ["c2.example.test"]
    malicious["iocs"]["registry"] = ["HKCU\\Run\\x"]
    malicious["iocs"]["mutex"] = ["Global\\m"]
    malicious["packed"] = True
    malicious["injection_count"] = 1
    malicious["yara_matches"] = ["Suspicious_Downloader", "C2_Gate_Url"]

    # When
    clean_score = triage._deterministic_score(clean, [])
    malicious_score = triage._deterministic_score(malicious, ["dropper", "trojan", "trojan", "trojan"])

    # Then
    assert clean_score == 0
    assert malicious_score == 10


def test_given_no_verdict_when_merge_verdict_then_rules_are_used():
    # Given
    triage = SampleTriage("x", MagicMock())
    result = _base_result()

    # When
    triage._merge_verdict(result, None, "dropper", 7, ["T1105"])

    # Then
    assert result["family_guess"] == "dropper"
    assert result["score"] == 7
    assert result["mitre_attack"] == ["T1105"]
    assert result["verdict_source"] == "regles (LLM indisponible)"


def test_given_llm_verdict_when_merge_verdict_then_llm_can_raise_score_and_complete_family():
    # Given
    client = MagicMock()
    client.backend = "mistral"
    triage = SampleTriage("x", MagicMock(), client)
    result = _base_result()
    verdict = {
        "family": "stealer",
        "mitre_attack": ["T1555"],
        "score": 10,
        "summary": "Vol de mots de passe.",
    }

    # When
    triage._merge_verdict(result, verdict, "unknown", 4, ["T1071"])

    # Then
    assert result["family_guess"] == "stealer"
    assert result["score"] == 6
    assert result["mitre_attack"] == ["T1071", "T1555"]
    assert result["llm_summary"] == "Vol de mots de passe."
    assert result["verdict_source"] == "regles + LLM (mistral)"


def test_given_results_when_fallback_summary_then_text_describes_the_sample():
    # Given
    triage = SampleTriage("x", MagicMock())
    result = _base_result()
    result["capabilities"] = ["capture du clavier (keylogger)"]
    result["iocs"]["domains"] = ["c2.example.test"]
    result["yara_matches"] = ["C2_Gate_Url"]
    result["injection_count"] = 2

    # When
    summary = triage._fallback_summary(result, "keylogger", 7)
    clean_summary = triage._fallback_summary(_base_result(), "unknown", 0)

    # Then
    assert "keylogger (score 7/10)" in summary
    assert "c2.example.test" in summary
    assert "2 texte(s)" in summary
    assert "probablement sain" in clean_summary
