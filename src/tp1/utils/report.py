import json
from datetime import datetime
from pathlib import Path

import pygal
from fpdf import FPDF

from tp1.utils.capture import Capture
from tp1.utils.config import logger

BAR_COLORS = [
    (52, 101, 164),
    (204, 0, 0),
    (78, 154, 6),
    (245, 121, 0),
    (117, 80, 123),
    (193, 125, 17),
    (6, 152, 154),
    (136, 138, 133),
]


class Report:
    def __init__(self, capture: Capture, filename: str, summary: str):
        self.capture = capture
        self.filename = filename
        self.title = "Rapport IDS/IPS - TP1"
        self.summary = summary
        self.array = []  # [protocole, nb paquets, %]
        self.graph = ""  # svg pygal

    def concat_report(self) -> str:
        """
        Concatenate report content
        :return:
        """
        content = self.title + "\n" + self.summary + "\n"
        for row in self.array:
            content += f"{row[0]}: {row[1]} paquets ({row[2]})\n"
        return content

    def save(self, filename: str) -> None:
        """
        Save report in a file
        :param filename:
        :return:
        """
        if not self.array:
            self.generate("array")
        if not self.graph:
            self.generate("graph")

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        pdf.set_font("Helvetica", "B", 18)
        pdf.cell(0, 12, self._clean_text(self.title), new_x="LMARGIN", new_y="NEXT", align="C")
        pdf.set_font("Helvetica", "", 10)
        source = self.capture.pcap_file if self.capture.pcap_file else f"interface {self.capture.interface}"
        date = datetime.now().strftime("%d/%m/%Y %H:%M")
        pdf.cell(
            0, 6, self._clean_text(f"Source : {source} - genere le {date}"), new_x="LMARGIN", new_y="NEXT"
        )
        pdf.ln(4)

        self._write_section_title(pdf, "1. Volume de paquets par protocole")
        self._draw_table(pdf)
        pdf.ln(4)

        self._write_section_title(pdf, "2. Graphique")
        self._draw_bar_chart(pdf)
        pdf.ln(4)

        self._write_section_title(pdf, "3. Analyse du trafic")
        self._write_analysis(pdf)
        pdf.ln(4)

        self._write_section_title(pdf, "4. Flag")
        pdf.set_font("Helvetica", "", 11)
        if self.capture.flag:
            flag_text = f"Flag trouve : {self.capture.flag}"
        else:
            flag_text = "Aucun flag trouve dans la capture."
        pdf.multi_cell(0, 6, self._clean_text(flag_text), new_x="LMARGIN", new_y="NEXT")

        Path(filename).parent.mkdir(parents=True, exist_ok=True)
        pdf.output(filename)
        logger.info(f"Rapport PDF enregistre dans {filename}")

        svg_filename = str(Path(filename).with_suffix("")) + "_graph.svg"
        with open(svg_filename, "w", encoding="utf-8") as svg_file:
            svg_file.write(self.graph)
        logger.info(f"Graphique SVG enregistre dans {svg_filename}")

    def save_json(self, filename: str) -> None:
        protocols = dict(self.capture.sort_network_protocols())
        attacks = [{"type": a["type"], "attacker": a["attacker"]} for a in self.capture.attacks]

        data = {"protocols": protocols, "attacks": attacks, "flag": self.capture.flag}
        Path(filename).parent.mkdir(parents=True, exist_ok=True)
        with open(filename, "w", encoding="utf-8") as json_file:
            json.dump(data, json_file, indent=2)
            json_file.write("\n")
        logger.info(f"Rapport JSON enregistre dans {filename}")

    def generate(self, param: str) -> None:
        """
        Generate graph and array
        """
        if param == "graph":
            chart = pygal.Bar(title="Nombre de paquets par protocole", show_legend=False, x_label_rotation=30)
            protocols = self.capture.sort_network_protocols()
            chart.x_labels = [name for name, _ in protocols]
            chart.add("Paquets", [count for _, count in protocols])
            self.graph = chart.render(is_unicode=True)
        elif param == "array":
            protocols = self.capture.sort_network_protocols()
            total = len(self.capture.packets)
            array = []
            for name, count in protocols:
                if total > 0:
                    percentage = f"{count * 100 / total:.1f} %"
                else:
                    percentage = "0.0 %"
                array.append([name, count, percentage])
            self.array = array

    def _write_section_title(self, pdf: FPDF, text: str) -> None:
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(52, 101, 164)
        pdf.cell(0, 10, self._clean_text(text), new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)

    def _draw_table(self, pdf: FPDF) -> None:
        column_widths = [70, 50, 50]
        headers = ["Protocole", "Nombre de paquets", "% des paquets"]

        pdf.set_font("Helvetica", "B", 11)
        pdf.set_fill_color(220, 220, 220)
        for width, header in zip(column_widths, headers):
            pdf.cell(width, 8, header, border=1, align="C", fill=True)
        pdf.ln()

        pdf.set_font("Helvetica", "", 11)
        for row in self.array:
            pdf.cell(column_widths[0], 7, self._clean_text(str(row[0])), border=1)
            pdf.cell(column_widths[1], 7, str(row[1]), border=1, align="C")
            pdf.cell(column_widths[2], 7, str(row[2]), border=1, align="C")
            pdf.ln()

        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(column_widths[0], 7, "Total paquets", border=1)
        pdf.cell(column_widths[1], 7, str(len(self.capture.packets)), border=1, align="C")
        pdf.cell(column_widths[2], 7, "", border=1)
        pdf.ln()

    def _draw_bar_chart(self, pdf: FPDF) -> None:
        # fpdf2 affiche mal le svg de pygal donc on redessine les barres à la main
        if len(self.array) == 0:
            pdf.set_font("Helvetica", "", 11)
            pdf.cell(0, 7, "Aucun paquet a afficher.", new_x="LMARGIN", new_y="NEXT")
            return

        label_width = 30
        max_bar_width = 120
        bar_height = 6
        space_between_bars = 2

        max_count = max(row[1] for row in self.array)

        needed_height = len(self.array) * (bar_height + space_between_bars)
        if pdf.get_y() + needed_height > pdf.page_break_trigger:
            pdf.add_page()

        pdf.set_font("Helvetica", "", 10)
        for i, (name, count, _) in enumerate(self.array):
            x = pdf.l_margin
            y = pdf.get_y()

            pdf.set_xy(x, y)
            pdf.cell(label_width, bar_height, self._clean_text(str(name)), align="R")

            bar_width = max(count * max_bar_width / max_count, 0.5)
            pdf.set_fill_color(*BAR_COLORS[i % len(BAR_COLORS)])
            pdf.rect(x + label_width + 2, y, bar_width, bar_height, style="F")

            pdf.set_xy(x + label_width + 4 + bar_width, y)
            pdf.cell(20, bar_height, str(count))

            pdf.set_xy(x, y + bar_height + space_between_bars)

    def _write_analysis(self, pdf: FPDF) -> None:
        attacks = self.capture.attacks
        pdf.set_font("Helvetica", "B", 12)

        if len(attacks) == 0:
            pdf.set_text_color(78, 154, 6)
            pdf.multi_cell(
                0,
                7,
                "Trafic legitime : aucune attaque detectee, tout va bien.",
                new_x="LMARGIN",
                new_y="NEXT",
            )
            pdf.set_text_color(0, 0, 0)
            return

        pdf.set_text_color(204, 0, 0)
        pdf.multi_cell(
            0, 7, f"Trafic illegitime : {len(attacks)} attaque(s) detectee(s).", new_x="LMARGIN", new_y="NEXT"
        )
        pdf.set_text_color(0, 0, 0)
        pdf.ln(2)

        for number, attack in enumerate(attacks, start=1):
            pdf.set_font("Helvetica", "B", 11)
            pdf.multi_cell(
                0,
                6,
                self._clean_text(f"Attaque {number} : {attack['type']}"),
                new_x="LMARGIN",
                new_y="NEXT",
            )
            pdf.set_font("Helvetica", "", 10)
            lines = [
                f"Protocole : {attack['protocol']}",
                f"Attaquant : {attack['attacker']}",
                f"Detail : {attack['details']}",
                f"Blocage propose : {attack['block_rule']}",
            ]
            for line in lines:
                pdf.multi_cell(0, 5, self._clean_text(line), new_x="LMARGIN", new_y="NEXT", align="L")
            pdf.ln(2)

    def _clean_text(self, text: str) -> str:
        # les polices de base de fpdf ne gèrent que le latin-1
        return text.encode("latin-1", errors="replace").decode("latin-1")
