"""
PDF Generator for RegRadar Objective 1 Technical Report.
Builds a high-quality, publication-grade PDF using native PDF operators.
Zero external library dependencies (pure standard library: zlib, struct, re).
"""

import sys
import zlib
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Any

# ==============================================================================
# Helvetica Character Width Table (Adobe Font Metrics - 1000 units per em)
# ==============================================================================

HELVETICA_WIDTHS = {
    ' ': 278, '!': 278, '"': 355, '#': 556, '$': 556, '%': 889, '&': 667, "'": 191,
    '(': 333, ')': 333, '*': 389, '+': 584, ',': 278, '-': 333, '.': 278, '/': 278,
    '0': 556, '1': 556, '2': 556, '3': 556, '4': 556, '5': 556, '6': 556, '7': 556,
    '8': 556, '9': 556, ':': 278, ';': 278, '<': 584, '=': 584, '>': 584, '?': 556,
    '@': 1015, 'A': 667, 'B': 667, 'C': 722, 'D': 722, 'E': 667, 'F': 611, 'G': 778,
    'H': 722, 'I': 278, 'J': 500, 'K': 667, 'L': 556, 'M': 833, 'N': 722, 'O': 778,
    'P': 667, 'Q': 778, 'R': 722, 'S': 667, 'T': 611, 'U': 722, 'V': 667, 'W': 944,
    'X': 667, 'Y': 667, 'Z': 611, '[': 278, '\\': 278, ']': 278, '^': 469, '_': 556,
    '`': 333, 'a': 556, 'b': 556, 'c': 500, 'd': 556, 'e': 556, 'f': 278, 'g': 556,
    'h': 556, 'i': 222, 'j': 222, 'k': 500, 'l': 222, 'm': 833, 'n': 556, 'o': 556,
    'p': 556, 'q': 556, 'r': 333, 's': 500, 't': 278, 'u': 556, 'v': 500, 'w': 722,
    'x': 500, 'y': 500, 'z': 500, '{': 334, '|': 260, '}': 334, '~': 584
}

HELVETICA_BOLD_WIDTHS = {
    ' ': 278, '!': 333, '"': 474, '#': 556, '$': 556, '%': 889, '&': 722, "'": 238,
    '(': 333, ')': 333, '*': 389, '+': 584, ',': 278, '-': 333, '.': 278, '/': 278,
    '0': 556, '1': 556, '2': 556, '3': 556, '4': 556, '5': 556, '6': 556, '7': 556,
    '8': 556, '9': 556, ':': 333, ';': 333, '<': 584, '=': 584, '>': 584, '?': 611,
    '@': 975, 'A': 722, 'B': 722, 'C': 722, 'D': 722, 'E': 667, 'F': 611, 'G': 778,
    'H': 722, 'I': 278, 'J': 556, 'K': 722, 'L': 611, 'M': 833, 'N': 722, 'O': 778,
    'P': 667, 'Q': 778, 'R': 722, 'S': 667, 'T': 611, 'U': 722, 'V': 667, 'W': 944,
    'X': 667, 'Y': 667, 'Z': 611, '[': 333, '\\': 278, ']': 333, '^': 584, '_': 556,
    '`': 333, 'a': 556, 'b': 611, 'c': 556, 'd': 611, 'e': 556, 'f': 333, 'g': 611,
    'h': 611, 'i': 278, 'j': 278, 'k': 556, 'l': 278, 'm': 889, 'n': 611, 'o': 611,
    'p': 611, 'q': 611, 'r': 389, 's': 556, 't': 333, 'u': 611, 'v': 556, 'w': 778,
    'x': 556, 'y': 556, 'z': 500, '{': 389, '|': 280, '}': 389, '~': 584
}

def string_width(text: str, font: str, size: float) -> float:
    """Computes exact string width in points."""
    if font == "Courier" or font == "Courier-Bold":
        return len(text) * 0.60 * size
    table = HELVETICA_BOLD_WIDTHS if "Bold" in font else HELVETICA_WIDTHS
    total = 0.0
    for ch in text:
        total += table.get(ch, 556)
    return (total / 1000.0) * size


def escape_pdf(text: str) -> str:
    """Escapes special characters in PDF literal text strings."""
    return text.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')


# ==============================================================================
# PDF Page & Document Builder
# ==============================================================================

class PDFPage:
    def __init__(self, page_num: int):
        self.page_num = page_num
        self.stream_ops: List[str] = []

    def add_op(self, op: str):
        self.stream_ops.append(op)

    def draw_rect(self, x: float, y: float, w: float, h: float,
                  fill_color: Optional[Tuple[float, float, float]] = None,
                  stroke_color: Optional[Tuple[float, float, float]] = None,
                  line_width: float = 1.0):
        ops = []
        if line_width != 1.0:
            ops.append(f"{line_width:.2f} w")
        if stroke_color:
            ops.append(f"{stroke_color[0]:.3f} {stroke_color[1]:.3f} {stroke_color[2]:.3f} RG")
        if fill_color:
            ops.append(f"{fill_color[0]:.3f} {fill_color[1]:.3f} {fill_color[2]:.3f} rg")
        ops.append(f"{x:.2f} {y:.2f} {w:.2f} {h:.2f} re")
        if fill_color and stroke_color:
            ops.append("B")
        elif fill_color:
            ops.append("f")
        elif stroke_color:
            ops.append("S")
        self.stream_ops.append("\n".join(ops))

    def draw_line(self, x1: float, y1: float, x2: float, y2: float,
                  stroke_color: Tuple[float, float, float] = (0, 0, 0),
                  line_width: float = 1.0, dashed: bool = False):
        ops = []
        if line_width != 1.0:
            ops.append(f"{line_width:.2f} w")
        ops.append(f"{stroke_color[0]:.3f} {stroke_color[1]:.3f} {stroke_color[2]:.3f} RG")
        if dashed:
            ops.append("[3 3] 0 d")
        else:
            ops.append("[] 0 d")
        ops.append(f"{x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S")
        self.stream_ops.append("\n".join(ops))

    def draw_text(self, text: str, x: float, y: float, font_tag: str, font_size: float,
                  color: Tuple[float, float, float] = (0.1, 0.1, 0.1)):
        escaped = escape_pdf(text)
        op = (
            f"BT\n"
            f"{color[0]:.3f} {color[1]:.3f} {color[2]:.3f} rg\n"
            f"/{font_tag} {font_size:.2f} Tf\n"
            f"{x:.2f} {y:.2f} Td\n"
            f"({escaped}) Tj\n"
            f"ET"
        )
        self.stream_ops.append(op)


class PDFDocument:
    def __init__(self, title: str):
        self.title = title
        self.pages: List[PDFPage] = []
        self.current_page: Optional[PDFPage] = None
        self.page_width = 612.0   # Letter width
        self.page_height = 792.0  # Letter height
        self.margin_left = 54.0
        self.margin_right = 54.0
        self.margin_top = 54.0
        self.margin_bottom = 54.0
        self.content_width = self.page_width - self.margin_left - self.margin_right # 504.0 pt
        self.cursor_y = self.page_height - self.margin_top

        # Color definitions
        self.c_navy = (0.08, 0.16, 0.28)        # #142947 Primary dark header
        self.c_slate = (0.20, 0.28, 0.38)       # #334761 Subheaders
        self.c_text = (0.12, 0.14, 0.18)        # #1f242e Body text
        self.c_muted = (0.42, 0.46, 0.52)       # #6b7585 Muted text
        self.c_bg_light = (0.96, 0.97, 0.98)    # #f5f7fa Box background
        self.c_border = (0.82, 0.85, 0.89)      # #d1d9e3 Border lines
        self.c_accent_blue = (0.14, 0.38, 0.74)  # Accent blue
        self.c_red = (0.85, 0.20, 0.20)         # Critical
        self.c_amber = (0.85, 0.55, 0.10)       # Intermediate
        self.c_green = (0.12, 0.60, 0.30)       # Leaf safe

        self.font_map = {
            "Helvetica": "F1",
            "Helvetica-Bold": "F2",
            "Helvetica-Oblique": "F3",
            "Courier": "F4",
            "Courier-Bold": "F5"
        }

        self.new_page()

    def new_page(self):
        page_num = len(self.pages) + 1
        page = PDFPage(page_num)
        self.pages.append(page)
        self.current_page = page
        self.cursor_y = self.page_height - self.margin_top - 24.0 # Leave room for header

    def ensure_space(self, needed_height: float):
        if self.cursor_y - needed_height < (self.margin_bottom + 20.0):
            self.new_page()

    def add_header_banner(self, title: str, subtitle: str, metadata: str):
        self.ensure_space(95)
        y = self.cursor_y

        # Top colored accent banner bar
        self.current_page.draw_rect(
            self.margin_left, y - 85, self.content_width, 85,
            fill_color=(0.95, 0.97, 1.0),
            stroke_color=self.c_accent_blue,
            line_width=1.5
        )
        # Left dark accent block
        self.current_page.draw_rect(
            self.margin_left, y - 85, 6.0, 85,
            fill_color=self.c_accent_blue,
            stroke_color=None
        )

        # Title
        self.current_page.draw_text(
            title, self.margin_left + 18, y - 26,
            self.font_map["Helvetica-Bold"], 15.0, self.c_navy
        )
        # Subtitle
        self.current_page.draw_text(
            subtitle, self.margin_left + 18, y - 48,
            self.font_map["Helvetica-Bold"], 10.5, self.c_slate
        )
        # Metadata
        self.current_page.draw_text(
            metadata, self.margin_left + 18, y - 68,
            self.font_map["Helvetica"], 8.5, self.c_muted
        )

        self.cursor_y = y - 100

    def add_h1(self, text: str):
        self.ensure_space(38)
        y = self.cursor_y - 12
        self.current_page.draw_text(
            text, self.margin_left, y,
            self.font_map["Helvetica-Bold"], 13.0, self.c_navy
        )
        # Subtle horizontal divider line under H1
        self.current_page.draw_line(
            self.margin_left, y - 5, self.margin_left + self.content_width, y - 5,
            stroke_color=self.c_border, line_width=0.75
        )
        self.cursor_y = y - 18

    def add_h2(self, text: str):
        self.ensure_space(28)
        y = self.cursor_y - 8
        self.current_page.draw_text(
            text, self.margin_left, y,
            self.font_map["Helvetica-Bold"], 10.5, self.c_slate
        )
        self.cursor_y = y - 14

    def add_h3(self, text: str):
        self.ensure_space(22)
        y = self.cursor_y - 6
        self.current_page.draw_text(
            text, self.margin_left, y,
            self.font_map["Helvetica-Bold"], 9.5, self.c_text
        )
        self.cursor_y = y - 12

    def add_paragraph(self, text: str, font: str = "Helvetica", size: float = 9.0,
                      leading: float = 12.8, color: Optional[Tuple[float, float, float]] = None,
                      indent: float = 0.0):
        color = color or self.c_text
        font_tag = self.font_map.get(font, "F1")
        max_w = self.content_width - indent

        words = text.split()
        lines = []
        cur_line = []
        cur_w = 0.0

        for word in words:
            w_word = string_width(word, font, size)
            w_space = string_width(' ', font, size)
            if cur_line and (cur_w + w_space + w_word > max_w):
                lines.append(" ".join(cur_line))
                cur_line = [word]
                cur_w = w_word
            else:
                if cur_line:
                    cur_w += w_space + w_word
                else:
                    cur_w = w_word
                cur_line.append(word)

        if cur_line:
            lines.append(" ".join(cur_line))

        for line in lines:
            self.ensure_space(leading)
            self.current_page.draw_text(
                line, self.margin_left + indent, self.cursor_y - size,
                font_tag, size, color
            )
            self.cursor_y -= leading

        self.cursor_y -= 4.0  # Spacing after paragraph

    def add_callout(self, lines: List[str], title: Optional[str] = None):
        box_height = len(lines) * 12.5 + (22 if title else 14)
        self.ensure_space(box_height + 10)
        y = self.cursor_y

        self.current_page.draw_rect(
            self.margin_left, y - box_height, self.content_width, box_height,
            fill_color=self.c_bg_light, stroke_color=self.c_border, line_width=0.75
        )
        self.current_page.draw_rect(
            self.margin_left, y - box_height, 3.5, box_height,
            fill_color=self.c_accent_blue, stroke_color=None
        )

        cur_y = y - 14
        if title:
            self.current_page.draw_text(
                title, self.margin_left + 12, cur_y,
                self.font_map["Helvetica-Bold"], 9.0, self.c_navy
            )
            cur_y -= 14

        for line in lines:
            self.current_page.draw_text(
                line, self.margin_left + 12, cur_y,
                self.font_map["Helvetica"], 8.5, self.c_text
            )
            cur_y -= 12.5

        self.cursor_y = y - box_height - 8

    def add_code_block(self, lines: List[str], caption: Optional[str] = None):
        line_h = 11.5
        box_h = len(lines) * line_h + (20 if caption else 12)
        self.ensure_space(box_h + 8)
        y = self.cursor_y

        self.current_page.draw_rect(
            self.margin_left, y - box_h, self.content_width, box_h,
            fill_color=(0.12, 0.15, 0.19), stroke_color=(0.25, 0.30, 0.38), line_width=0.5
        )

        cur_y = y - 13
        if caption:
            self.current_page.draw_text(
                caption, self.margin_left + 10, cur_y,
                self.font_map["Courier-Bold"], 8.0, (0.7, 0.8, 0.9)
            )
            cur_y -= 12

        for line in lines:
            self.current_page.draw_text(
                line, self.margin_left + 10, cur_y,
                self.font_map["Courier"], 7.8, (0.90, 0.92, 0.95)
            )
            cur_y -= line_h

        self.cursor_y = y - box_h - 8

    def add_table(self, headers: List[str], rows: List[List[str]], col_widths: List[float]):
        row_h = 16.0
        table_h = (len(rows) + 1) * row_h
        self.ensure_space(table_h + 15)
        y = self.cursor_y

        # Draw Header Row
        self.current_page.draw_rect(
            self.margin_left, y - row_h, self.content_width, row_h,
            fill_color=self.c_navy, stroke_color=self.c_border, line_width=0.5
        )

        cur_x = self.margin_left
        for i, h in enumerate(headers):
            self.current_page.draw_text(
                h, cur_x + 6, y - row_h + 4.5,
                self.font_map["Helvetica-Bold"], 8.0, (1.0, 1.0, 1.0)
            )
            cur_x += col_widths[i]

        # Draw Data Rows
        cur_y = y - row_h
        for r_idx, row in enumerate(rows):
            cur_y -= row_h
            bg = (0.97, 0.98, 0.99) if r_idx % 2 == 1 else (1.0, 1.0, 1.0)
            self.current_page.draw_rect(
                self.margin_left, cur_y, self.content_width, row_h,
                fill_color=bg, stroke_color=self.c_border, line_width=0.5
            )
            cur_x = self.margin_left
            for c_idx, val in enumerate(row):
                # Color code risk tiers or highlight percentages if relevant
                text_color = self.c_text
                font_name = "Helvetica"
                if val == "CRITICAL_ROOT" or "100%" in val:
                    font_name = "Helvetica-Bold"
                if val == "CRITICAL_ROOT":
                    text_color = self.c_red
                elif val == "INTERMEDIATE":
                    text_color = self.c_amber
                elif val == "LEAF_SAFE":
                    text_color = self.c_green

                self.current_page.draw_text(
                    val, cur_x + 6, cur_y + 4.5,
                    self.font_map[font_name], 7.8, text_color
                )
                cur_x += col_widths[c_idx]

        self.cursor_y = cur_y - 10

    def draw_pipeline_diagram(self):
        """Draws vector pipeline architecture diagram."""
        self.ensure_space(110)
        y = self.cursor_y - 5
        box_w = 110.0
        box_h = 44.0
        gap = 18.0
        top_y = y - 55

        # 4 Pipeline Stages
        stages = [
            ("1. Ingestion", "HCL Parser & AST", "python-hcl2"),
            ("2. Extraction", "Reference Extractor", "Module Resolver"),
            ("3. Compilation", "DAG Construction", "NetworkX DiGraph"),
            ("4. Governance", "Centrality & Blast Risk", "Risk Gate Tiers")
        ]

        for i, (stg_num, title, sub) in enumerate(stages):
            bx = self.margin_left + i * (box_w + gap)
            # Box
            self.current_page.draw_rect(
                bx, top_y, box_w, box_h,
                fill_color=(0.95, 0.97, 1.0),
                stroke_color=self.c_accent_blue,
                line_width=1.0
            )
            # Stage Tag
            self.current_page.draw_text(
                stg_num, bx + 8, top_y + 31,
                self.font_map["Helvetica-Bold"], 7.5, self.c_accent_blue
            )
            # Title
            self.current_page.draw_text(
                title, bx + 8, top_y + 19,
                self.font_map["Helvetica-Bold"], 7.8, self.c_navy
            )
            # Subtitle
            self.current_page.draw_text(
                sub, bx + 8, top_y + 8,
                self.font_map["Helvetica"], 7.0, self.c_muted
            )

            # Arrow to next stage
            if i < 3:
                ax1 = bx + box_w + 3
                ax2 = ax1 + gap - 6
                ay = top_y + (box_h / 2.0)
                self.current_page.draw_line(
                    ax1, ay, ax2, ay,
                    stroke_color=self.c_accent_blue, line_width=1.2
                )
                # Arrowhead
                self.current_page.draw_line(
                    ax2 - 3, ay + 3, ax2, ay,
                    stroke_color=self.c_accent_blue, line_width=1.2
                )
                self.current_page.draw_line(
                    ax2 - 3, ay - 3, ax2, ay,
                    stroke_color=self.c_accent_blue, line_width=1.2
                )

        # Bottom Gating Branches
        gate_y = top_y - 32
        self.current_page.draw_rect(
            self.margin_left + 140, gate_y, 224, 24,
            fill_color=self.c_bg_light, stroke_color=self.c_border, line_width=0.75
        )
        self.current_page.draw_text(
            "Gate Decision: S(v) >= 0.40 or D(v) >= 0.35 => CRITICAL_ROOT",
            self.margin_left + 148, gate_y + 8,
            self.font_map["Helvetica-Bold"], 7.2, self.c_navy
        )

        self.cursor_y = gate_y - 12

    def draw_topology_diagram(self):
        """Draws vector diagram of multi-tier cloud topology."""
        self.ensure_space(140)
        y = self.cursor_y - 5

        # Root VPC
        self.current_page.draw_rect(
            self.margin_left + 170, y - 30, 164, 26,
            fill_color=(1.0, 0.92, 0.92), stroke_color=self.c_red, line_width=1.2
        )
        self.current_page.draw_text(
            "aws_vpc.prod_vpc [Score: 0.3333]", self.margin_left + 180, y - 20,
            self.font_map["Helvetica-Bold"], 7.5, self.c_red
        )
        self.current_page.draw_text(
            "CRITICAL_ROOT - Mutate Blocked", self.margin_left + 180, y - 28,
            self.font_map["Helvetica"], 6.5, self.c_red
        )

        # Mid Tier (Subnet & Security Group)
        y_mid = y - 75
        self.current_page.draw_rect(
            self.margin_left + 60, y_mid, 160, 26,
            fill_color=(1.0, 0.96, 0.88), stroke_color=self.c_amber, line_width=1.0
        )
        self.current_page.draw_text(
            "aws_subnet.app_subnet [0.1257]", self.margin_left + 70, y_mid + 14,
            self.font_map["Helvetica-Bold"], 7.2, self.c_amber
        )
        self.current_page.draw_text(
            "INTERMEDIATE - Transit Node", self.margin_left + 70, y_mid + 6,
            self.font_map["Helvetica"], 6.5, self.c_amber
        )

        self.current_page.draw_rect(
            self.margin_left + 284, y_mid, 160, 26,
            fill_color=(1.0, 0.96, 0.88), stroke_color=self.c_amber, line_width=1.0
        )
        self.current_page.draw_text(
            "aws_security_group.app_sg [0.0628]", self.margin_left + 294, y_mid + 14,
            self.font_map["Helvetica-Bold"], 7.2, self.c_amber
        )
        self.current_page.draw_text(
            "INTERMEDIATE - Ingress Rules", self.margin_left + 294, y_mid + 6,
            self.font_map["Helvetica"], 6.5, self.c_amber
        )

        # Leaf Tier (EC2 Instance)
        y_leaf = y - 125
        self.current_page.draw_rect(
            self.margin_left + 170, y_leaf, 164, 26,
            fill_color=(0.90, 0.98, 0.92), stroke_color=self.c_green, line_width=1.0
        )
        self.current_page.draw_text(
            "aws_instance.app_server [0.0013]", self.margin_left + 180, y_leaf + 14,
            self.font_map["Helvetica-Bold"], 7.5, self.c_green
        )
        self.current_page.draw_text(
            "LEAF_SAFE - Auto-Remediate Permitted", self.margin_left + 180, y_leaf + 6,
            self.font_map["Helvetica"], 6.5, self.c_green
        )

        # Connector Lines
        # VPC -> Subnet
        self.current_page.draw_line(
            self.margin_left + 210, y - 30, self.margin_left + 140, y_mid + 26,
            stroke_color=self.c_muted, line_width=0.8
        )
        # VPC -> SG
        self.current_page.draw_line(
            self.margin_left + 290, y - 30, self.margin_left + 364, y_mid + 26,
            stroke_color=self.c_muted, line_width=0.8
        )
        # Subnet -> EC2
        self.current_page.draw_line(
            self.margin_left + 140, y_mid, self.margin_left + 210, y_leaf + 26,
            stroke_color=self.c_muted, line_width=0.8
        )
        # SG -> EC2
        self.current_page.draw_line(
            self.margin_left + 364, y_mid, self.margin_left + 290, y_leaf + 26,
            stroke_color=self.c_muted, line_width=0.8
        )

        self.cursor_y = y_leaf - 12

    def render_decorations(self):
        """Draws running headers and footers on all pages."""
        total_pages = len(self.pages)
        for page in self.pages:
            # Running Header (top rule + title)
            page.draw_line(
                self.margin_left, self.page_height - 38,
                self.margin_left + self.content_width, self.page_height - 38,
                stroke_color=self.c_border, line_width=0.5
            )
            page.draw_text(
                "RegRadar Technical Report: AST Parsing & Centrality Risk Bounding",
                self.margin_left, self.page_height - 32,
                self.font_map["Helvetica"], 7.2, self.c_muted
            )
            page.draw_text(
                "Objective 1 Research & Architecture",
                self.margin_left + self.content_width - 150, self.page_height - 32,
                self.font_map["Helvetica"], 7.2, self.c_muted
            )

            # Running Footer (bottom rule + page count)
            page.draw_line(
                self.margin_left, 42,
                self.margin_left + self.content_width, 42,
                stroke_color=self.c_border, line_width=0.5
            )
            page.draw_text(
                "Autonomous IaC Governance & Graph-Theoretic Verification",
                self.margin_left, 30,
                self.font_map["Helvetica"], 7.0, self.c_muted
            )
            page_str = f"Page {page.page_num} of {total_pages}"
            page.draw_text(
                page_str, self.margin_left + self.content_width - 55, 30,
                self.font_map["Helvetica-Bold"], 7.2, self.c_slate
            )

    def write_pdf(self, output_path: str):
        """Serializes document object graph into standard PDF 1.4 binary format."""
        self.render_decorations()

        pdf_bytes = bytearray()
        pdf_bytes.extend(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")

        offsets = []
        obj_id = 1

        def append_obj(content: bytes) -> int:
            nonlocal obj_id
            offsets.append(len(pdf_bytes))
            header = f"{obj_id} 0 obj\n".encode("ascii")
            footer = b"\nendobj\n"
            pdf_bytes.extend(header)
            pdf_bytes.extend(content)
            pdf_bytes.extend(footer)
            current_id = obj_id
            obj_id += 1
            return current_id

        # Font Objects
        f1_id = append_obj(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
        f2_id = append_obj(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
        f3_id = append_obj(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Oblique >>")
        f4_id = append_obj(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")
        f5_id = append_obj(b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier-Bold >>")

        # Page Contents & Objects
        page_obj_ids = []
        for page in self.pages:
            content_str = "\n".join(page.stream_ops)
            compressed = zlib.compress(content_str.encode("latin-1"))
            stream_obj = (
                f"<< /Length {len(compressed)} /Filter /FlateDecode >>\nstream\n".encode("ascii")
                + compressed +
                b"\nendstream"
            )
            content_id = append_obj(stream_obj)

            page_def = (
                f"<< /Type /Page\n"
                f"   /Parent 2 0 R\n"
                f"   /MediaBox [0 0 {self.page_width} {self.page_height}]\n"
                f"   /Contents {content_id} 0 R\n"
                f"   /Resources << /Font << /F1 {f1_id} 0 R /F2 {f2_id} 0 R /F3 {f3_id} 0 R /F4 {f4_id} 0 R /F5 {f5_id} 0 R >> >>\n"
                f">>"
            ).encode("ascii")
            p_id = append_obj(page_def)
            page_obj_ids.append(p_id)

        # Pages Catalog & Root Catalog
        kids_str = " ".join([f"{pid} 0 R" for pid in page_obj_ids])
        pages_def = (
            f"<< /Type /Pages\n"
            f"   /Kids [{kids_str}]\n"
            f"   /Count {len(page_obj_ids)}\n"
            f">>"
        ).encode("ascii")
        pages_id = append_obj(pages_def)

        catalog_def = f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode("ascii")
        catalog_id = append_obj(catalog_def)

        # Xref Table
        xref_offset = len(pdf_bytes)
        total_objs = obj_id
        pdf_bytes.extend(f"xref\n0 {total_objs}\n".encode("ascii"))
        pdf_bytes.extend(b"0000000000 65535 f \n")
        for off in offsets:
            pdf_bytes.extend(f"{off:010d} 00000 n \n".encode("ascii"))

        # Trailer
        trailer = (
            f"trailer\n"
            f"<< /Size {total_objs}\n"
            f"   /Root {catalog_id} 0 R\n"
            f">>\n"
            f"startxref\n"
            f"{xref_offset}\n"
            f"%%EOF\n"
        ).encode("ascii")
        pdf_bytes.extend(trailer)

        with open(output_path, "wb") as f:
            f.write(pdf_bytes)


# ==============================================================================
# Document Content Construction
# ==============================================================================

def build_technical_report(output_file: str):
    doc = PDFDocument(title="RegRadar Objective 1 Technical Report")

    # Document Header Banner
    doc.add_header_banner(
        title="Infrastructure as Code Dependency Modeling & Risk Bounding",
        subtitle="RegRadar Governance Research: AST Ingestion, DAG Compilation, and Graph Centrality",
        metadata="Date: November 2026 | Scope: Objective 1 Technical Architecture & Empirical Analysis"
    )

    # --------------------------------------------------------------------------
    # Section 1: System Architecture
    # --------------------------------------------------------------------------
    doc.add_h1("1. System Architecture")
    doc.add_paragraph(
        "RegRadar processes declarative cloud infrastructure configurations through a deterministic pipeline "
        "that converts source code into an evaluation graph. The architecture separates configuration parsing "
        "from policy enforcement, using a directed acyclic graph (DAG) to capture the dependency topology of cloud "
        "resources before evaluating risk."
    )

    doc.add_h2("1.1 Ingestion and Analysis Pipeline Flow")
    doc.draw_pipeline_diagram()

    doc.add_paragraph(
        "The system comprises three primary subsystems: Ingestion, Graph Compilation, and Centrality Evaluation. "
        "The Ingestion Subsystem uses HCLParser to transform HashiCorp Configuration Language files into an AST dictionary. "
        "During this phase, ReferenceExtractor identifies explicit dependencies (such as depends_on declarations) and "
        "implicit references (such as attribute interpolations like aws_vpc.main.id). When configurations reference "
        "local child modules, ModuleResolver recursively maps parent inputs and child outputs into fully qualified "
        "hierarchical resource identifiers."
    )
    doc.add_paragraph(
        "The Graph Compilation Subsystem uses DependencyGraphBuilder to construct a NetworkX directed graph G = (V, E). "
        "Nodes correspond to managed cloud resources or data sources. Directed edges (u, v) establish that resource v "
        "depends on resource u (u -> v). This direction convention guarantees that all downstream dependents of a resource u "
        "appear as reachable descendants in graph traversals."
    )
    doc.add_paragraph(
        "The Centrality and Blast-Radius Evaluation Subsystem uses CentralityEngine to calculate betweenness centrality, "
        "eigenvector centrality, and cascading descendant counts. It normalizes these values and computes a composite "
        "blast-radius risk score for each resource. The score dictates the risk tier assigned to the resource and determines "
        "whether automated remediation tools may mutate its attributes without human review."
    )

    doc.add_h2("1.2 Multi-Tier Dependency Graph Topology")
    doc.draw_topology_diagram()

    doc.add_paragraph(
        "In the multi-tier topology shown above, aws_vpc.prod_vpc acts as the root network container. Resources flow "
        "from root nodes through intermediate transit infrastructure (subnets, route tables, security groups) down to "
        "terminal leaf nodes (EC2 compute instances and S3 encryption attachments). Modifying aws_vpc.prod_vpc causes "
        "cascading operational impact across all downstream children, whereas mutating leaf attributes carries zero "
        "cascading consequence."
    )

    # --------------------------------------------------------------------------
    # Section 2: Objective 1: Definition and Measurable Outcomes
    # --------------------------------------------------------------------------
    doc.add_h1("2. Objective 1: Definition and Measurable Outcomes")
    doc.add_h2("2.1 Formal Definition")
    doc.add_paragraph(
        "Objective 1 establishes a deterministic ingestion pipeline that parses raw declarative configurations (Terraform HCL) "
        "into normalized Abstract Syntax Trees (AST), compiles a Directed Acyclic Graph (DAG) explicitly modeling cross-resource "
        "bindings and parent-child hierarchies, and formulates a graph-theoretic risk gate using betweenness and eigenvector "
        "centrality metrics to algorithmically evaluate blast-radius risk and constrain automated remediation strictly to safe, "
        "low-centrality leaf attributes."
    )
    doc.add_paragraph(
        "Automated infrastructure remediation tools frequently cause unexpected service interruptions when they alter "
        "resources that support widespread downstream dependencies. Objective 1 addresses this problem by calculating "
        "the topological blast radius of each resource before permitting automated mutations."
    )

    doc.add_h2("2.2 Measurable Outcomes")
    doc.add_callout([
        "1. Deterministic Graph Construction: 100% acyclicity verification (is_dag = True) across all valid benchmarks.",
        "2. Reference Resolution Accuracy: >= 98% resolution of implicit and explicit bindings across cloud providers.",
        "3. Blast-Radius Mutation Containment: 100% block rate on autonomous mutations targeting CRITICAL_ROOT infrastructure.",
        "4. Execution Latency: Mean processing time under 100 milliseconds for topologies with up to 100 resources."
    ], title="Quantitative Performance Targets")

    # --------------------------------------------------------------------------
    # Section 3: Objective 1: Technical Planning
    # --------------------------------------------------------------------------
    doc.add_h1("3. Objective 1: Technical Planning")
    doc.add_h2("3.1 Algorithmic Traversal and Identifier Resolution")
    doc.add_paragraph(
        "The parsing pipeline maps raw declarative text to structured graph nodes through four stages: lexical parsing, "
        "identifier sanitization, recursive attribute traversal, and module linkage. Identifiers are converted into a canonical "
        "dot-delimited format: resource_type.resource_name. Hierarchical module resources receive prefixed paths of the form "
        "module.mod_name.resource_type.resource_name. Regular expressions isolate candidate identifiers from complex expressions, "
        "ternaries, and string templates while filtering out language keywords and built-in prefixes."
    )

    doc.add_h2("3.2 Mathematical Formulation of Centrality Metrics")
    doc.add_paragraph(
        "The dependency graph is represented as G = (V, E), where V is the set of resources and E is the set of directed edges. "
        "Because edge (u, v) denotes that resource v depends on resource u (u -> v), all resources affected by mutating u "
        "are contained in the set of reachable descendants: Descendants(u) = { w in V | directed path from u to w }."
    )
    doc.add_paragraph(
        "The engine calculates four graph-theoretic metrics for every node v in V:"
    )

    doc.add_callout([
        "Betweenness Centrality:   C_B(v) = sum_{s != v != t} [ sigma_{st}(v) / sigma_{st} ]",
        "Eigenvector Centrality:   lambda * C_E(v) = sum_{u in V} [ A_{uv} * C_E(u) ]",
        "Descendant Ratio:         D(v) = |Descendants(v)| / (|V| - 1)",
        "Out-Degree Ratio:         O(v) = OutDeg(v) / (|V| - 1)"
    ], title="Centrality Formulations across Dependency Graph G = (V, E)")

    doc.add_paragraph(
        "Betweenness centrality identifies transit resources that bridge disparate architectural components, even when "
        "their total degree is low. Eigenvector centrality reflects transitive structural influence: resources that connect "
        "to other high-impact nodes receive elevated ratings. The descendant ratio captures the total cascading blast radius, "
        "and out-degree ratio measures immediate downstream dependents."
    )

    doc.add_h2("3.3 Composite Blast-Radius Formulation and Gating Logic")
    doc.add_paragraph(
        "The composite blast-radius score S(v) in [0.0, 1.0] combines these measures using calibrated weights:"
    )
    doc.add_callout([
        "S(v) = 0.40 * D(v) + 0.25 * C_B(v) + 0.20 * C_E(v) + 0.15 * O(v)",
        "",
        "Risk Gating Decision Rules:",
        "  If InDeg(v) == 0 and OutDeg(v) == 0:        Tier = LEAF_SAFE,    AutoRemediate = True",
        "  Else If S(v) >= 0.40 or D(v) >= 0.35:       Tier = CRITICAL_ROOT, AutoRemediate = False",
        "  Else If S(v) >= 0.15 or |Descendants(v)| > 0: Tier = INTERMEDIATE, AutoRemediate = True (Scoped)",
        "  Else:                                       Tier = LEAF_SAFE,    AutoRemediate = True"
    ], title="Composite Blast-Radius Risk Metric & Policy Enforcement")

    doc.add_paragraph(
        "When a resource is classified as CRITICAL_ROOT, automated agents are strictly prohibited from applying repairs. "
        "The modification is packaged as an operator proposal requiring interactive human sign-off in the console."
    )

    # --------------------------------------------------------------------------
    # Section 4: Objective 1: Analysis and Interpretation of Results
    # --------------------------------------------------------------------------
    doc.add_h1("4. Objective 1: Analysis and Interpretation of Results")
    doc.add_h2("4.1 Empirical Centrality Distribution Across Cloud Providers")
    doc.add_paragraph(
        "Testing the pipeline across real-world benchmark configurations reveals consistent structural asymmetry in declarative code. "
        "Root containers such as virtual networks, resource groups, and main routing tables occupy high-out-degree positions "
        "(In-Degree = 0, Out-Degree > 0). Terminal resources like EC2 instances, storage containers, and encryption bindings "
        "occupy leaf positions (In-Degree > 0, Out-Degree = 0)."
    )
    doc.add_paragraph(
        "Resources in the LEAF_SAFE tier consistently exhibit blast-radius scores below 0.01. For example, aws_instance.app_server "
        "in the multi-tier benchmark has a score of 0.0013, and aws_s3_bucket_server_side_encryption_configuration.log_encryption "
        "has a score of 0.0000. These resources have zero downstream descendants (D(v) = 0). Modifying an encryption rule or an "
        "instance tag cannot cause a cascading outage in parent subnets or databases. Automated remediation can safely patch these attributes."
    )
    doc.add_paragraph(
        "In contrast, azurerm_resource_group.rg_gdpr in the ecommerce benchmark exhibits a composite score of 0.5200 and a "
        "descendant ratio of 1.0000. Modifying or destroying this resource causes the cloud provider to cascade deletions across "
        "all contained subnets, security groups, and storage accounts. Setting the critical threshold tau_score = 0.40 and "
        "tau_desc = 0.35 reliably intercepts these nodes."
    )

    doc.add_h2("4.2 Failure Modes of Degree Centrality Alone")
    doc.add_paragraph(
        "Conventional static analyzers that evaluate risk using simple in-degree and out-degree metrics fail to detect critical "
        "transit infrastructure. Consider aws_db_subnet_group.hipaa_db_subnets in the healthcare benchmark: it has an in-degree of 2 "
        "and an out-degree of 1. If evaluated solely by degree centrality, this resource appears low risk because its out-degree is only 1. "
        "However, the resource possesses a betweenness centrality of 0.0536, the highest betweenness in the entire configuration. "
        "It sits directly on the shortest path linking the underlying network subnets to the production patient database. "
        "A change to this resource breaks database connectivity for all dependent application tiers. The composite formula S(v), "
        "which weights betweenness at 0.25, elevates this resource into the INTERMEDIATE tier rather than misclassifying it as a safe leaf."
    )
    doc.add_paragraph(
        "Similarly, in the multi-tier benchmark, aws_route_table.public_rt has an out-degree of 1 and an in-degree of 2, yet it achieves "
        "a betweenness of 0.0208 and an eigenvector score of 0.0031. Eigenvector centrality reflects the fact that its sole downstream "
        "dependent is aws_route_table_association.public_assoc, which directly controls the routing of aws_subnet.app_subnet. "
        "Incorporating eigenvector centrality ensures that resources connected to structurally sensitive nodes receive proportional risk scores."
    )

    # --------------------------------------------------------------------------
    # Section 5: Objective 1: Result Snapshot
    # --------------------------------------------------------------------------
    doc.add_h1("5. Objective 1: Result Snapshot")
    doc.add_paragraph(
        "The following table summarizes the evaluation of the graph compilation and centrality risk engine across six benchmark topologies:"
    )

    headers = ["Benchmark Configuration", "Nodes |V|", "Edges |E|", "Roots", "Transit", "Leaves", "Critical Block Rate", "Latency"]
    rows = [
        ["simple_vpc", "2", "1", "1", "1", "0", "100% (1/1)", "4.82 ms"],
        ["fintech_pci_aws", "8", "6", "1", "4", "3", "100% (1/1)", "73.19 ms"],
        ["healthcare_hipaa_aws", "9", "6", "1", "5", "3", "100% (1/1)", "14.52 ms"],
        ["ecommerce_gdpr_azure", "6", "6", "1", "2", "3", "100% (1/1)", "13.88 ms"],
        ["multi_tier", "10", "11", "1", "7", "2", "100% (1/1)", "18.24 ms"],
        ["multicloud_hybrid", "5", "2", "1", "0", "4", "100% (1/1)", "7.38 ms"]
    ]
    col_w = [140.0, 48.0, 48.0, 42.0, 44.0, 44.0, 84.0, 54.0]
    doc.add_table(headers, rows, col_w)

    doc.add_paragraph(
        "The evaluation demonstrates three consistent empirical findings: "
        "(1) Zero Acyclicity Violations: Every tested configuration compiled into a verified DAG (is_dag = True). "
        "(2) Full Containment of Root Mutators: In all benchmarks, root resources whose modification compromises the network "
        "boundary (aws_vpc, azurerm_resource_group, google_compute_network) were intercepted by the risk gate with a 100% block rate. "
        "(3) Low Processing Latency: Parsing, AST resolution, and centrality calculation completed in an average of 22.0 milliseconds per configuration."
    )

    # --------------------------------------------------------------------------
    # Section 6: Conclusion
    # --------------------------------------------------------------------------
    doc.add_h1("6. Conclusion")
    doc.add_paragraph(
        "Combining AST parsing with graph-theoretic centrality metrics provides a deterministic method for evaluating risk "
        "in declarative infrastructure code. Lexical reference extraction accurately resolves cross-resource dependencies across "
        "multi-cloud configurations, compiling them into a directed acyclic graph."
    )
    doc.add_paragraph(
        "Calculating betweenness and eigenvector centrality alongside cascading descendant counts eliminates the blindness of "
        "simple degree-based counting. Resources that act as structural bridges or foundational roots receive higher risk ratings, "
        "allowing the governance engine to block unsafe automated changes while permitting automated repairs on low-risk leaf nodes."
    )

    # --------------------------------------------------------------------------
    # Section 7: Future Work
    # --------------------------------------------------------------------------
    doc.add_h1("7. Future Work")
    doc.add_paragraph(
        "Three planned extensions will build on this dependency graph foundation:"
    )
    doc.add_callout([
        "1. Integration with Plan Execution Diffs: Correlating the graph with serialized execution plans (terraform plan -json)",
        "   will enable the engine to calculate the delta blast radius of planned state changes, identifying whether an update",
        "   requires in-place attribute modification or full resource recreation.",
        "2. Incremental Subgraph Re-evaluation: Implementing an incremental graph solver will allow the engine to invalidate",
        "   and recompute centrality metrics only for subgraphs directly affected by modified files.",
        "3. Cross-Repository Dependency Federation: Extending the reference extractor to ingest remote state references",
        "   (terraform_remote_state) will allow compiling a unified global dependency graph across independent repositories."
    ], title="Future Research Directions")

    # Write output to disk
    doc.write_pdf(output_file)
    print(f"Successfully generated PDF: {output_file} ({len(doc.pages)} pages)")


if __name__ == "__main__":
    out_path = sys.argv[1] if len(sys.argv) > 1 else "regradar_objective_1_technical_report.pdf"
    build_technical_report(out_path)
