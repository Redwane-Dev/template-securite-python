import json
from unittest.mock import MagicMock, patch

from fpdf import FPDF

from src.tp2.utils.report import OUTPUT_KEYS, Report, generate_report


def _result(score: int = 8) -> dict:
    return {
        "name": "sample1_dropper.bin",
        "sha256": "a" * 64,
        "md5": "b" * 32,
        "size": 1234,
        "entropy": 4.8,
        "file_type": "ELF 64-bit LSB pie executable, x86-64",
        "iocs": {
            "domains": ["c2.example.test"],
            "ips": ["185.1.2.3"],
            "urls": [],
            "mutex": [],
            "registry": [],
            "paths": [],
        },
        "imports": ["URLDownloadToFileA", "malloc"],
        "suspicious_apis": ["URLDownloadToFileA"],
        "yara_matches": ["C2_Gate_Url"],
        "capabilities": ["telechargement"],
        "family_guess": "dropper",
        "mitre_attack": ["T1105"],
        "llm_summary": "Resume — avec un tiret long",
        "score": score,
        "flag": "ESGI{test}",
        "injection_count": 1,
        "verdict_source": "regles",
    }


def _output(result: dict) -> dict:
    output = {key: result[key] for key in OUTPUT_KEYS}
    output["iocs"] = {key: value for key, value in result["iocs"].items() if key != "paths"}
    return output


def _pdf() -> FPDF:
    pdf = FPDF()
    pdf.add_page()
    return pdf


def test_given_results_when_init_then_attributes_are_set():
    # Given
    results = [_result()]

    # When
    report = Report(results, [_output(results[0])])

    # Then
    assert report.results == results
    assert report.title == "Rapport de triage de malware - TP2"


def test_given_output_when_save_json_then_file_is_written_under_each_expected_name(tmp_path):
    # Given
    result = _result()
    report = Report([result], [_output(result)])
    out = tmp_path / "out"

    # When
    written = report.save_json(str(out))

    # Then
    expected_names = [f"{'a' * 64}.json", "sample1_dropper.bin.triage.json", "sample1_dropper.triage.json"]
    assert written == [str(out / name) for name in expected_names]
    for name in expected_names:
        data = json.loads((out / name).read_text(encoding="utf-8"))
        assert list(data.keys()) == OUTPUT_KEYS
        assert data["flag"] == "ESGI{test}"


def test_given_name_without_extension_when_json_file_names_then_no_duplicate():
    # Given
    report = Report([], [])

    # When
    names = report._json_file_names("abc", "sample")

    # Then
    assert names == ["abc.json", "sample.triage.json"]


def test_given_results_when_save_pdf_then_pdf_is_created(tmp_path):
    # Given
    results = [_result(8), _result(5), _result(1)]
    report = Report(results, [])

    # When
    report.save_pdf(str(tmp_path / "rapport.pdf"))

    # Then
    assert (tmp_path / "rapport.pdf").read_bytes().startswith(b"%PDF")


def test_given_results_when_draw_overview_table_then_table_is_written():
    # Given
    pdf = _pdf()
    report = Report([_result()], [])
    start_y = pdf.get_y()

    # When
    report._draw_overview_table(pdf)

    # Then
    assert pdf.get_y() > start_y


def test_given_result_when_write_sample_then_page_is_filled():
    # Given
    pdf = _pdf()
    report = Report([], [])
    start_y = pdf.get_y()

    # When
    report._write_sample(pdf, _result())

    # Then
    assert pdf.get_y() > start_y + 50


def test_given_text_when_write_section_title_then_cursor_moves_down():
    # Given
    pdf = _pdf()
    start_y = pdf.get_y()

    # When
    Report([], [])._write_section_title(pdf, "Titre")

    # Then
    assert pdf.get_y() > start_y


def test_given_lines_when_write_lines_then_each_line_is_written():
    # Given
    pdf = _pdf()
    start_y = pdf.get_y()

    # When
    Report([], [])._write_lines(pdf, ["ligne 1", "ligne 2"])

    # Then
    assert pdf.get_y() == start_y + 10


def test_given_scores_when_score_color_then_color_depends_on_score():
    # Given
    report = Report([], [])

    # When / Then
    assert report._score_color(9) == (204, 0, 0)
    assert report._score_color(5) == (245, 121, 0)
    assert report._score_color(1) == (78, 154, 6)


def test_given_unicode_and_long_word_when_clean_text_then_text_is_latin1_and_cut():
    # Given
    text = "tiret — " + "x" * 200

    # When
    result = Report([], [])._clean_text(text)

    # Then
    assert result.startswith("tiret ? ")
    assert max(len(word) for word in result.split(" ")) == 90


def test_given_results_when_generate_report_then_json_and_pdf_are_written(tmp_path):
    # Given
    result = _result()

    # When
    written = generate_report([result], [_output(result)], str(tmp_path))

    # Then
    assert len(written) == 3  # <sha256>.json + <echantillon>.triage.json avec et sans extension
    assert (tmp_path / "triage_report.pdf").exists()


def test_given_pdf_error_when_generate_report_then_json_are_still_written(tmp_path):
    # Given
    result = _result()

    # When
    with patch.object(Report, "save_pdf", MagicMock(side_effect=RuntimeError("fpdf"))):
        written = generate_report([result], [_output(result)], str(tmp_path), str(tmp_path / "r.pdf"))

    # Then
    assert len(written) == 3  # <sha256>.json + <echantillon>.triage.json avec et sans extension
    assert not (tmp_path / "r.pdf").exists()
