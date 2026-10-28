import sys

from src.config import logging

logger = logging.getLogger("TP3")

# logger dedie aux deux lignes de resultat attendues sur stdout, sans
# le format global (horodatage, niveau) herite de la config partagee
result_logger = logging.getLogger("TP3.result")
result_logger.propagate = False
result_logger.setLevel(logging.INFO)
if not result_logger.handlers:
    _stdout_handler = logging.StreamHandler(sys.stdout)
    _stdout_handler.setFormatter(logging.Formatter("%(message)s"))
    result_logger.addHandler(_stdout_handler)