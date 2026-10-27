import json

from src.tp2.main import _list_samples, _parse_arguments, main


def test_given_contract_options_when_parse_arguments_then_options_are_read():
    # Given
    arguments = ["--samples", "s", "--rules", "r", "--out", "o", "--no-llm"]

    # When
    args = _parse_arguments(arguments)

    # Then
    assert args.samples == "s"
    assert args.rules == "r"
    assert args.out == "o"
    assert args.no_llm is True
    assert args.pdf is None


def test_given_folder_when_list_samples_then_hidden_files_and_out_dir_are_skipped(tmp_path):
    # Given
    (tmp_path / "a.bin").write_bytes(b"a")
    (tmp_path / ".hidden").write_bytes(b"h")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.exe").write_bytes(b"b")
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "old.json").write_text("{}")

    # When
    samples = _list_samples(str(tmp_path), str(tmp_path / "out"))

    # Then
    assert [path.replace("\\", "/").split("/")[-1] for path in samples] == ["a.bin", "b.exe"]


def test_given_missing_folder_when_list_samples_then_return_empty_list(tmp_path):
    # When
    samples = _list_samples(str(tmp_path / "absent"), str(tmp_path / "out"))

    # Then
    assert samples == []


def test_given_samples_when_main_then_one_json_per_sample_is_written(tmp_path, sample_data, no_llm_env):
    # Given
    samples = tmp_path / "samples"
    samples.mkdir()
    (samples / "dropper.bin").write_bytes(sample_data)
    (samples / "clean.txt").write_text("rien de suspect ici")
    out = tmp_path / "out"

    # When
    exit_code = main(["--samples", str(samples), "--rules", str(tmp_path / "rules"), "--out", str(out)])

    # Then
    assert exit_code == 0
    reports = sorted(out.glob("*.json"))
    assert len(reports) == 2
    flags = sorted(json.loads(path.read_text(encoding="utf-8"))["flag"] for path in reports)
    assert flags == ["", "ESGI{vrai_flag_123}"]
    assert (out / "triage_report.pdf").exists()


def test_given_empty_folder_when_main_then_return_error_code(tmp_path, no_llm_env):
    # When
    exit_code = main(["--samples", str(tmp_path), "--out", str(tmp_path / "out")])

    # Then
    assert exit_code == 1
