import argparse
from pathlib import Path

from scapy.error import Scapy_Exception

from tp1.utils.capture import Capture
from tp1.utils.config import logger
from tp1.utils.report import Report


def _parse_arguments(arguments: list[str] | None = None) -> argparse.Namespace:
    """
    Lit les options de la ligne de commande
    """
    parser = argparse.ArgumentParser(prog="tp1", description="IDS/IPS maison : analyse d'une capture reseau")
    parser.add_argument("--pcap", help="fichier PCAP a analyser (sinon capture en direct)")
    parser.add_argument("--iface", help="interface reseau a ecouter (ex: eth0)")
    parser.add_argument("--out", default="report.json", help="fichier JSON de sortie (defaut: report.json)")
    parser.add_argument("--pdf", help="fichier PDF de sortie (defaut: meme nom que --out en .pdf)")
    parser.add_argument("--count", type=int, default=200, help="nombre de paquets a capturer en direct")
    parser.add_argument("--timeout", type=int, default=30, help="duree max de la capture en direct (s)")
    return parser.parse_args(arguments)


def main(arguments: list[str] | None = None) -> int:
    args = _parse_arguments(arguments)
    logger.info("Starting TP1")

    capture = Capture(interface=args.iface, pcap_file=args.pcap)
    try:
        capture.capture_traffic(count=args.count, timeout=args.timeout)
    except (OSError, Scapy_Exception) as error:
        logger.error(f"Impossible de recuperer le trafic : {error}")
        return 1

    capture.analyse()
    summary = capture.get_summary()
    logger.info(f"Resume :\n{summary}")

    filename = args.pdf or str(Path(args.out).with_suffix(".pdf"))

    report = Report(capture, filename, summary)
    report.generate("graph")
    report.generate("array")

    # json d'abord, c'est lui qui sert pour la correction
    report.save_json(args.out)
    try:
        report.save(filename)
    except Exception as error:
        logger.error(f"Erreur pendant la creation du PDF : {error}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
