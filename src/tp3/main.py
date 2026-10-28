"""
TP3 - Breach the target.

Enchaine une phase web (fuzzing + captcha) et une phase reseau
(decodage chronometre) pour obtenir le drapeau final.

    poetry run tp3 --target http://127.0.0.1:8080
    python -m tp3.main --target http://127.0.0.1:8080
"""

import argparse

from tp3.utils.config import logger, result_logger
from tp3.utils.net import NetworkPhase
from tp3.utils.web import WebPhase


def _parse_arguments(arguments: list[str] | None = None) -> argparse.Namespace:
    """
    Lit les options de la ligne de commande.

    :param arguments: arguments a parser (None pour sys.argv)
    :return: options analysees
    """
    parser = argparse.ArgumentParser(prog="tp3", description="Breach the target")
    parser.add_argument("--target", required=True, help="URL de la cible (ex: http://127.0.0.1:8080)")
    return parser.parse_args(arguments)


def main(arguments: list[str] | None = None) -> int:
    """
    Point d'entree du TP3 : enchaine la phase web et la phase reseau.

    :param arguments: arguments a parser (None pour sys.argv)
    :return: 0 si le drapeau final est obtenu, 1 sinon
    """
    args = _parse_arguments(arguments)
    logger.info("Starting TP3 - breach the target")

    try:
        web_phase = WebPhase(args.target)
        flag1, host, port, key = web_phase.run()
        result_logger.info(f"[+] FLAG1: {flag1}")
    except RuntimeError as error:
        logger.error(f"Phase web echouee : {error}")
        return 1

    try:
        network_phase = NetworkPhase(host, port, key)
        flag_final = network_phase.run()
        result_logger.info(f"[+] FLAG_FINAL: {flag_final}")
    except RuntimeError as error:
        logger.error(f"Phase reseau echouee : {error}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())