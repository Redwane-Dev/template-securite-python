import argparse
from pathlib import Path

from tp2.utils.config import logger
from tp2.utils.llm import LLMClient
from tp2.utils.report import generate_report
from tp2.utils.scanner import YaraScanner
from tp2.utils.triage import SampleTriage


def _parse_arguments(arguments: list[str] | None = None) -> argparse.Namespace:
    """
    Lit les options de la ligne de commande
    """
    parser = argparse.ArgumentParser(prog="tp2", description="Triage automatise de malware")
    parser.add_argument("--samples", required=True, help="dossier des echantillons a analyser")
    parser.add_argument("--rules", default="rules", help="dossier des regles YARA (defaut: rules)")
    parser.add_argument("--out", default="out", help="dossier de sortie, un JSON par echantillon")
    parser.add_argument("--pdf", help="chemin du rapport PDF (defaut: <out>/triage_report.pdf)")
    parser.add_argument(
        "--no-llm", action="store_true", help="ne pas appeler de LLM (verdict par les regles)"
    )
    return parser.parse_args(arguments)


def _list_samples(samples_dir: str, out_dir: str) -> list[str]:
    """
    Liste les fichiers a analyser (sous-dossiers compris), sans les fichiers caches ni le dossier de sortie
    """
    folder = Path(samples_dir)
    if not folder.is_dir():
        return []
    output_folder = Path(out_dir).resolve()
    samples = []
    for path in sorted(folder.rglob("*")):
        if not path.is_file() or path.name.startswith("."):
            continue
        if output_folder in path.resolve().parents:
            continue
        samples.append(str(path))
    return samples


def main(arguments: list[str] | None = None) -> int:
    args = _parse_arguments(arguments)
    logger.info("Starting TP2")

    samples = _list_samples(args.samples, args.out)
    if not samples:
        logger.error(f"Aucun echantillon trouve dans {args.samples}")
        return 1
    logger.info(f"{len(samples)} echantillon(s) a analyser")

    scanner = YaraScanner(args.rules)
    llm_client = None if args.no_llm else LLMClient()

    results = []
    outputs = []
    for sample in samples:
        triage = SampleTriage(sample, scanner, llm_client)
        try:
            results.append(triage.run())
        except (OSError, ValueError) as error:
            logger.error(f"Analyse impossible pour {sample} : {error}")
            continue
        outputs.append(triage.to_output())

    generate_report(results, outputs, args.out, args.pdf)
    logger.info(f"Triage termine : {len(outputs)} rapport(s) JSON dans {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
