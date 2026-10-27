from src.tp2.utils.scanner import CUSTOM_RULE_NAMES, YaraScanner, yara_scan

PROVIDED_RULE = """
rule Has_Mutex
{
    strings:
        $mutex = "Global\\\\" ascii
    condition:
        $mutex
}
"""


def test_custom_rule_names():
    # Then
    assert len(CUSTOM_RULE_NAMES) >= 2
    assert "Prompt_Injection_Attempt" in CUSTOM_RULE_NAMES


def test_given_no_rules_dir_when_init_then_only_custom_rules_are_loaded():
    # When
    scanner = YaraScanner()

    # Then
    assert scanner.rules is not None
    assert scanner.rule_files == []


def test_given_no_rule_at_all_when_init_then_rules_is_none():
    # When
    scanner = YaraScanner(use_custom_rules=False)

    # Then
    assert scanner.rules is None
    assert scanner.scan(b"anything") == []


def test_given_sample_when_scan_then_custom_rules_match(sample_data):
    # Given
    scanner = YaraScanner()

    # When
    matches = scanner.scan(sample_data)

    # Then
    assert "Prompt_Injection_Attempt" in matches
    assert "Registry_Run_Persistence" in matches
    assert "C2_Gate_Url" in matches
    assert "Packed_High_Entropy" not in matches


def test_given_random_data_when_scan_then_packed_rule_matches():
    # Given
    data = bytes(range(256)) * 64

    # When
    matches = YaraScanner().scan(data)

    # Then
    assert "Packed_High_Entropy" in matches


def test_given_rules_dir_when_compile_rules_then_provided_rules_are_added(tmp_path, sample_data):
    # Given
    (tmp_path / "provided.yar").write_text(PROVIDED_RULE)
    scanner = YaraScanner(str(tmp_path), use_custom_rules=False)

    # When
    rules = scanner._compile_rules()

    # Then
    assert [match.rule for match in rules.match(data=sample_data)] == ["Has_Mutex"]


def test_given_invalid_rule_file_when_compile_rules_then_file_is_skipped(tmp_path):
    # Given
    (tmp_path / "broken.yar").write_text("rule Broken { condition: }")

    # When
    scanner = YaraScanner(str(tmp_path))

    # Then
    assert scanner.rule_files == []
    assert scanner.rules is not None


def test_given_rules_dir_when_find_rule_files_then_only_rule_extensions_are_listed(tmp_path):
    # Given
    (tmp_path / "a.yar").write_text(PROVIDED_RULE)
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.yara").write_text(PROVIDED_RULE)
    (tmp_path / "readme.md").write_text("pas une regle")
    scanner = YaraScanner(use_custom_rules=False)
    scanner.rules_dir = str(tmp_path)

    # When
    files = scanner._find_rule_files()

    # Then
    assert [path.name for path in files] == ["a.yar", "b.yara"]


def test_given_missing_dir_when_find_rule_files_then_return_empty_list():
    # Given
    scanner = YaraScanner("dossier/qui/n/existe/pas")

    # When
    files = scanner._find_rule_files()

    # Then
    assert files == []


def test_given_rules_dir_when_yara_scan_then_provided_and_custom_rules_match(tmp_path, sample_data):
    # Given
    (tmp_path / "provided.yar").write_text(PROVIDED_RULE)

    # When
    matches = yara_scan(sample_data, str(tmp_path))

    # Then
    assert "Has_Mutex" in matches
    assert "Prompt_Injection_Attempt" in matches
