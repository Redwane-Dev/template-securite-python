import json
from datetime import datetime
from pathlib import Path

from fpdf import FPDF

from tp2.utils.config import logger

OUTPUT_KEYS = [
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


class Report:
    def __init__(self, results: list[dict], outputs: list[dict]) -> None:
        # results : resultats complets (pour le PDF) ; outputs : JSON au format de la correction
        self.results = results
        self.outputs = outputs
        self.title = "Rapport de triage de malware - TP2"

    def save_json(self, out_dir: str) -> list[str]:
        """
        Ecrit le JSON de chaque echantillon sous les noms attendus par la correction

        :param out_dir: dossier de sortie
        :return: chemins des fichiers ecrits
        """
        folder = Path(out_dir)
        folder.mkdir(parents=True, exist_ok=True)
        written = []

        for output, result in zip(self.outputs, self.results):
            ordered = {key: output[key] for key in OUTPUT_KEYS}
            for file_name in self._json_file_names(output["sha256"], result["name"]):
                json_path = folder / file_name
                with open(json_path, "w", encoding="utf-8") as json_file:
                    json.dump(ordered, json_file, indent=2, ensure_ascii=False)
                    json_file.write("\n")
                written.append(str(json_path))
                logger.info(f"JSON enregistre : {json_path}")
        return written

    def _json_file_names(self, sha256: str, sample_name: str) -> list[str]:
        """
        La consigne demande <sha256>.json mais la moulinette cherche <echantillon>.triage.json :
        on ecrit les deux, avec et sans l'extension de l'echantillon

        :param sha256: empreinte de l'echantillon
        :param sample_name: nom du fichier de l'echantillon
        :return: noms des fichiers JSON, sans doublon
        """
        name = Path(sample_name).name
        names = [f"{sha256}.json", f"{name}.triage.json", f"{Path(name).stem}.triage.json"]
        return list(dict.fromkeys(names))

    def save_pdf(self, pdf_path: str) -> None:
        """
        Ecrit le rapport PDF lisible : une page de synthese puis une page par echantillon

        :param pdf_path: chemin du PDF
        """
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)

        pdf.add_page()
        pdf.set_font("Helvetica", "B", 18)
        pdf.cell(0, 12, self._clean_text(self.title), new_x="LMARGIN", new_y="NEXT", align="C")
        pdf.set_font("Helvetica", "", 10)
        date = datetime.now().strftime("%d/%m/%Y %H:%M")
        pdf.cell(
            0, 6, f"Genere le {date} - {len(self.results)} echantillon(s)", new_x="LMARGIN", new_y="NEXT"
        )
        pdf.ln(4)
        self._draw_overview_table(pdf)

        for result in self.results:
            pdf.add_page()
            self._write_sample(pdf, result)

        Path(pdf_path).parent.mkdir(parents=True, exist_ok=True)
        pdf.output(pdf_path)
        logger.info(f"Rapport PDF enregistre : {pdf_path}")

    def _draw_overview_table(self, pdf: FPDF) -> None:
        """
        Tableau de synthese : un echantillon par ligne avec famille, score et nombre d'IOC
        """
        self._write_section_title(pdf, "Synthese")
        widths = [60, 30, 18, 20, 62]
        headers = ["Echantillon", "Famille", "Score", "IOC", "Flag"]
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_fill_color(220, 220, 220)
        for width, header in zip(widths, headers):
            pdf.cell(width, 8, header, border=1, align="C", fill=True)
        pdf.ln()

        pdf.set_font("Helvetica", "", 9)
        for result in self.results:
            ioc_count = 0
            for key, values in result["iocs"].items():
                if key != "paths":
                    ioc_count += len(values)

            red, green, blue = self._score_color(result["score"])
            pdf.cell(widths[0], 7, self._clean_text(result["name"][:34]), border=1)
            pdf.cell(widths[1], 7, self._clean_text(result["family_guess"]), border=1, align="C")
            pdf.set_text_color(red, green, blue)
            pdf.cell(widths[2], 7, f"{result['score']}/10", border=1, align="C")
            pdf.set_text_color(0, 0, 0)
            pdf.cell(widths[3], 7, str(ioc_count), border=1, align="C")

            flag_text = result["flag"]
            if not flag_text:
                flag_text = "-"
            pdf.cell(widths[4], 7, self._clean_text(flag_text), border=1)
            pdf.ln()

    def _write_sample(self, pdf: FPDF, result: dict) -> None:
        """
        Page detaillee d'un echantillon
        """
        pdf.set_font("Helvetica", "B", 15)
        pdf.cell(0, 10, self._clean_text(f"Echantillon : {result['name']}"), new_x="LMARGIN", new_y="NEXT")

        self._write_section_title(pdf, "Verdict")
        red, green, blue = self._score_color(result["score"])
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(red, green, blue)
        pdf.cell(
            0,
            7,
            self._clean_text(f"Famille : {result['family_guess']} - score {result['score']}/10"),
            new_x="LMARGIN",
            new_y="NEXT",
        )
        pdf.set_text_color(0, 0, 0)

        pdf.set_fill_color(230, 230, 230)
        pdf.rect(pdf.l_margin, pdf.get_y() + 1, 100, 4, style="F")
        pdf.set_fill_color(red, green, blue)
        pdf.rect(pdf.l_margin, pdf.get_y() + 1, 10 * result["score"], 4, style="F")
        pdf.ln(7)

        mitre = ", ".join(result["mitre_attack"]) if result["mitre_attack"] else "-"
        flag = result["flag"] if result["flag"] else "aucun"

        self._write_lines(
            pdf,
            [
                f"Source du verdict : {result.get('verdict_source', '')}",
                f"Resume : {result['llm_summary']}",
                f"MITRE ATT&CK : {mitre}",
                f"Flag : {flag}",
            ],
        )

        self._write_section_title(pdf, "Empreintes et fichier")
        self._write_lines(
            pdf,
            [
                f"SHA-256 : {result['sha256']}",
                f"MD5 : {result['md5']}",
                f"Taille : {result['size']} octets - entropie {result['entropy']}",
                f"Type : {result['file_type']}",
            ],
        )

        self._write_section_title(pdf, "Indicateurs de compromission")
        lines = []
        for key, values in result["iocs"].items():
            if values:
                lines.append(f"{key} : {', '.join(values)}")
            else:
                lines.append(f"{key} : -")
        self._write_lines(pdf, lines)

        self._write_section_title(pdf, "Analyse")

        yara = ", ".join(result["yara_matches"]) if result["yara_matches"] else "-"
        apis = ", ".join(result["suspicious_apis"]) if result["suspicious_apis"] else "-"
        caps = ", ".join(result["capabilities"]) if result["capabilities"] else "-"

        self._write_lines(
            pdf,
            [
                f"Regles YARA : {yara}",
                f"API suspectes : {apis}",
                f"Capacites : {caps}",
                f"Imports ({len(result['imports'])}) : {', '.join(result['imports'][:25])}",
                f"Injections de prompt ignorees : {result['injection_count']}",
            ],
        )

    def _write_section_title(self, pdf: FPDF, text: str) -> None:
        """
        Titre de section en bleu
        """
        pdf.ln(2)
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(52, 101, 164)
        pdf.cell(0, 8, self._clean_text(text), new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)

    def _write_lines(self, pdf: FPDF, lines: list[str]) -> None:
        """
        Ecrit une liste de lignes (elles passent a la ligne si elles sont trop longues)
        """
        pdf.set_font("Helvetica", "", 9)
        for line in lines:
            pdf.multi_cell(0, 5, self._clean_text(line), new_x="LMARGIN", new_y="NEXT", align="L")

    def _score_color(self, score: int) -> tuple[int, int, int]:
        """
        Vert pour un score faible, orange pour moyen, rouge pour eleve
        """
        if score >= 7:
            return (204, 0, 0)
        if score >= 4:
            return (245, 121, 0)
        return (78, 154, 6)

    def _clean_text(self, text: str) -> str:
        """
        Les polices de base de fpdf2 ne gerent que le latin-1 ; on coupe aussi les mots tres longs
        (hash, URL) pour qu'ils puissent passer a la ligne
        """
        words = []
        for word in str(text).split(" "):
            while len(word) > 90:
                words.append(word[:90])
                word = word[90:]
            words.append(word)
        return " ".join(words).encode("latin-1", errors="replace").decode("latin-1")


def generate_report(
    results: list[dict], outputs: list[dict], out_dir: str, pdf_path: str | None = None
) -> list[str]:
    """
    Genere les rapports : un JSON par echantillon (machine-lisible) et un PDF (lisible)

    :param results: resultats complets de l'analyse
    :param outputs: resultats au format JSON de la correction
    :param out_dir: dossier des JSON
    :param pdf_path: chemin du PDF (par defaut <out_dir>/triage_report.pdf)
    :return: chemins des JSON ecrits
    """
    report = Report(results, outputs)
    written = report.save_json(out_dir)
    if pdf_path is None:
        pdf_path = str(Path(out_dir) / "triage_report.pdf")
    try:
        report.save_pdf(pdf_path)
    except Exception as error:
        # si le pdf plante on continue quand meme
        logger.error(f"Erreur pendant la creation du PDF : {error}")
    return written
