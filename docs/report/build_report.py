"""Build the AgentGuard project report (.docx + .pdf) in the department format.

    python3 docs/report/build_report.py            # figures must exist (figures/make_figures.py)

Pipeline:
  1. content/*.md (chapters), content/00_front.toml, abbreviations.toml, references.toml
  2. python-docx renders the document: A4, margins T1 B1 L1.5 R1 in, Times New Roman 12,
     1.5 spacing, black text; 3 sections (unnumbered / roman / arabic).
  3. LibreOffice converts to PDF; pdftotext gives the real page of every heading and caption;
     the static Table of Contents, List of Tables and List of Figures are rebuilt with those
     numbers until they are stable (a Word TOC field wraps the static TOC so Word can update it).

Content markup (a small Markdown subset):
  # Title            numbered chapter ("Chapter N: Title"), new page
  #* Title           unnumbered top-level part (Conclusion, Appendices, ...), new page
  ## Title           numbered section N.M;   ##* Title  unnumbered section (appendices)
  - item / 1. item   bullet / numbered list items
  ::figure key | file | caption | width_in
  ::table key | caption   (+ optional ::widths a,b,c) followed by a pipe table
  ::code ... ::endcode    monospace block
  {fig:key} {tab:key}     cross-references;  [@key; @key2]  citations
  **bold**  *italic*  `code`
"""

from __future__ import annotations

import copy
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK, WD_LINE_SPACING, WD_TAB_ALIGNMENT, WD_TAB_LEADER
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

HERE = Path(__file__).resolve().parent
CONTENT = HERE / "content"
FIGS = HERE / "figures"
ASSETS = HERE / "assets"
OUT_DOCX = HERE / "AgentGuard_Report.docx"
OUT_PDF = HERE / "AgentGuard_Report.pdf"

# ----------------------------------------------------------------------------------- SETTINGS
SETTINGS = {
    "STUDENT_NAME": "Akshat Singh",
    "ROLL_NUMBER": "[roll number]",
    "DEPARTMENT": "[e.g. Department of Computer Science and Engineering]",
    "GUIDE_NAME": "[guide name]",
    "GUIDE_DESIG": "[guide designation]",
    "EXAMINER_NAME": "",
    "REPORT_KIND": "Seminar Report",
    "DEGREE": "Bachelor of Technology",
    "YEAR": "2026",
    "PLACE": "Gandhinagar",
    "DATE": "[insert date]",
    "PROJECT_TITLE": "AgentGuard: A Risk-Adaptive, Tamper-Evident Security and Audit Gateway for AI Agents",
}

FONT = "Times New Roman"
MONO = "Courier New"
BLACK = RGBColor(0, 0, 0)
BLUE = RGBColor(0x0B, 0x2D, 0x6B)  # single deep-blue accent, cover title only
TEXT_W = 8.27 - 1.5 - 1.0  # A4 width minus left/right margins (inches)


def S(text: str) -> str:
    for k, v in SETTINGS.items():
        text = text.replace("{" + k + "}", v)
    return text


# ----------------------------------------------------------------------------------- parsing
@dataclass
class Block:
    kind: str                     # chapter, part, section, usection, para, bullet, number, figure, table, code
    text: str = ""
    key: str = ""
    file: str = ""
    width: float = 5.6
    rows: list[list[str]] = field(default_factory=list)
    widths: list[float] = field(default_factory=list)
    label: str = ""               # assigned number, e.g. "3.1" / "Chapter 3" / "A.1"
    lines: list[str] = field(default_factory=list)


def parse(md: str) -> list[Block]:
    blocks: list[Block] = []
    lines = md.splitlines()
    i = 0
    para: list[str] = []

    def flush():
        if para:
            blocks.append(Block("para", " ".join(s.strip() for s in para)))
            para.clear()

    while i < len(lines):
        ln = lines[i]
        s = ln.strip()
        if not s:
            flush(); i += 1; continue
        if s.startswith("#* "):
            flush(); blocks.append(Block("part", s[3:].strip()))
        elif s.startswith("##* "):
            flush(); blocks.append(Block("usection", s[4:].strip()))
        elif s.startswith("## "):
            flush(); blocks.append(Block("section", s[3:].strip()))
        elif s.startswith("# "):
            flush(); blocks.append(Block("chapter", s[2:].strip()))
        elif s.startswith("::figure"):
            flush()
            parts = [p.strip() for p in s[len("::figure"):].split("|")]
            blocks.append(Block("figure", key=parts[0], file=parts[1], text=parts[2],
                                width=float(parts[3]) if len(parts) > 3 else 5.6))
        elif s.startswith("::table"):
            flush()
            key, cap = [p.strip() for p in s[len("::table"):].split("|", 1)]
            b = Block("table", key=key, text=cap)
            i += 1
            if lines[i].strip().startswith("::widths"):
                b.widths = [float(x) for x in lines[i].strip()[len("::widths"):].split(",")]
                i += 1
            while i < len(lines) and lines[i].strip().startswith("|"):
                row = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                if not all(re.fullmatch(r":?-+:?", c) for c in row):
                    b.rows.append(row)
                i += 1
            blocks.append(b)
            continue
        elif s == "::code":
            flush()
            b = Block("code")
            i += 1
            while lines[i].strip() != "::endcode":
                b.lines.append(lines[i]); i += 1
            blocks.append(b)
        elif re.match(r"^- ", s):
            flush(); blocks.append(Block("bullet", s[2:].strip()))
        elif re.match(r"^\d+\. ", s):
            flush()
            m = re.match(r"^(\d+)\. (.*)", s)
            blocks.append(Block("number", m.group(2), label=m.group(1)))
        elif blocks and blocks[-1].kind in ("bullet", "number") and not para and ln.startswith("   "):
            blocks[-1].text += " " + s
        else:
            para.append(s)
        i += 1
    flush()
    return blocks


def load_content():
    blocks: list[Block] = []
    for p in sorted(CONTENT.glob("0[1-9]_*.md")):
        blocks += parse(p.read_text(encoding="utf-8"))
    return blocks


def number(blocks: list[Block]):
    """Assign chapter/section/figure/table numbers; return the key -> label map."""
    refs: dict[str, str] = {}
    ch = 0
    sec = 0
    prefix = ""
    fig = tab = 0
    for b in blocks:
        if b.kind == "chapter":
            ch += 1; sec = 0; fig = tab = 0; prefix = str(ch)
            b.label = f"Chapter {ch}"
        elif b.kind == "part":
            prefix = ""
        elif b.kind == "section":
            sec += 1
            b.label = f"{ch}.{sec}"
        elif b.kind == "usection":
            m = re.match(r"Appendix ([A-Z])", b.text)
            if m:
                prefix = m.group(1); fig = tab = 0
        elif b.kind == "figure":
            fig += 1; b.label = f"{prefix}.{fig}"; refs["fig:" + b.key] = "Figure " + b.label
        elif b.kind == "table":
            tab += 1; b.label = f"{prefix}.{tab}"; refs["tab:" + b.key] = "Table " + b.label
    return refs


def load_refs():
    data = tomllib.loads((CONTENT / "references.toml").read_text(encoding="utf-8"))
    order = sorted(data, key=lambda k: data[k]["sort"].lower())
    return {k: i + 1 for i, k in enumerate(order)}, [data[k]["text"] for k in order]


# ----------------------------------------------------------------------------------- docx helpers
def set_run_font(run, size=12, bold=None, italic=None, font=FONT, color=BLACK):
    run.font.name = font
    run.font.size = Pt(size)
    run.font.color.rgb = color
    if bold is not None:
        run.font.bold = bold
    if italic is not None:
        run.font.italic = italic
    rpr = run._element.get_or_add_rPr()
    rfonts = rpr.find(qn("w:rFonts"))
    if rfonts is None:
        rfonts = OxmlElement("w:rFonts"); rpr.insert(0, rfonts)
    for a in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"):
        rfonts.set(qn(a), font)


def style_fonts(style, size, bold=False, font=FONT):
    style.font.name = font
    style.font.size = Pt(size)
    style.font.bold = bold
    style.font.color.rgb = BLACK
    rpr = style.element.get_or_add_rPr()
    rfonts = rpr.find(qn("w:rFonts"))
    if rfonts is None:
        rfonts = OxmlElement("w:rFonts"); rpr.insert(0, rfonts)
    for a in list(rfonts.attrib):
        if "Theme" in a or "theme" in a:
            del rfonts.attrib[a]
    for a in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"):
        rfonts.set(qn(a), font)
    # drop theme colour
    c = rpr.find(qn("w:color"))
    if c is not None:
        for a in list(c.attrib):
            if "theme" in a.lower():
                del c.attrib[a]


INLINE = re.compile(r"(\*\*.+?\*\*|`[^`]+`|\*[^*\s][^*]*\*)")


def add_inline(p, text, size=12, base_bold=False, mono_size=None):
    for part in INLINE.split(text):
        if not part:
            continue
        if part.startswith("**") and part.endswith("**"):
            r = p.add_run(part[2:-2]); set_run_font(r, size, bold=True)
        elif part.startswith("`") and part.endswith("`"):
            r = p.add_run(part[1:-1]); set_run_font(r, mono_size or size - 1.5, font=MONO, bold=base_bold)
        elif part.startswith("*") and part.endswith("*") and len(part) > 2:
            r = p.add_run(part[1:-1]); set_run_font(r, size, italic=True, bold=base_bold)
        else:
            r = p.add_run(part); set_run_font(r, size, bold=base_bold)


def pfmt(p, align=WD_ALIGN_PARAGRAPH.JUSTIFY, before=0, after=6, line=1.5, keep_next=False, indent=None,
         first=None, page_break=False):
    f = p.paragraph_format
    p.alignment = align
    f.space_before = Pt(before)
    f.space_after = Pt(after)
    f.line_spacing = line
    f.keep_with_next = keep_next
    f.widow_control = True
    if indent is not None:
        f.left_indent = Inches(indent)
    if first is not None:
        f.first_line_indent = Inches(first)
    if page_break:
        f.page_break_before = True
    return p


def page_break(doc):
    p = doc.add_paragraph()
    p.add_run().add_break(WD_BREAK.PAGE)
    pfmt(p, after=0, line=1.0)


def fld_simple(p, instr, size=12):
    r = p.add_run()
    set_run_font(r, size)
    for kind, val in (("begin", None), ("instr", instr), ("separate", None), ("text", "1"), ("end", None)):
        if kind == "instr":
            el = OxmlElement("w:instrText"); el.set(qn("xml:space"), "preserve"); el.text = val
            r._element.append(el)
        elif kind == "text":
            t = OxmlElement("w:t"); t.text = val; r._element.append(t)
        else:
            el = OxmlElement("w:fldChar"); el.set(qn("w:fldCharType"), kind); r._element.append(el)


def field_char(p, kind, instr=None):
    r = p.add_run()
    el = OxmlElement("w:fldChar"); el.set(qn("w:fldCharType"), kind)
    if kind == "begin":
        el.set(qn("w:dirty"), "false")
    r._element.append(el)
    if instr:
        r2 = p.add_run()
        it = OxmlElement("w:instrText"); it.set(qn("xml:space"), "preserve"); it.text = instr
        r2._element.append(it)
        r3 = p.add_run()
        sep = OxmlElement("w:fldChar"); sep.set(qn("w:fldCharType"), "separate"); r3._element.append(sep)


def set_section(section, fmt=None, start=None):
    section.page_height = Inches(11.69)
    section.page_width = Inches(8.27)
    section.top_margin = Inches(1.0)
    section.bottom_margin = Inches(1.0)
    section.left_margin = Inches(1.5)
    section.right_margin = Inches(1.0)
    section.footer_distance = Inches(0.5)
    sp = section._sectPr
    for old in sp.findall(qn("w:pgNumType")) + sp.findall(qn("w:pgBorders")):
        sp.remove(old)
    # single solid black page border, 1 pt, 24 pt from the page edge (inside the printable area,
    # outside the text, header and footer areas)
    pb = OxmlElement("w:pgBorders")
    pb.set(qn("w:offsetFrom"), "page")
    for side in ("top", "left", "bottom", "right"):
        e = OxmlElement(f"w:{side}")
        e.set(qn("w:val"), "single"); e.set(qn("w:sz"), "8"); e.set(qn("w:space"), "24"); e.set(qn("w:color"), "000000")
        pb.append(e)
    sp.find(qn("w:pgMar")).addnext(pb)  # schema order: pgSz, pgMar, paperSrc, pgBorders, ..., pgNumType
    if fmt:
        pg = OxmlElement("w:pgNumType")
        pg.set(qn("w:fmt"), fmt)
        if start is not None:
            pg.set(qn("w:start"), str(start))
        cols = sp.find(qn("w:cols"))  # schema order: ... pgMar, pgNumType, cols, docGrid ...
        if cols is not None:
            cols.addprevious(pg)
        else:
            sp.append(pg)


def footer_page_number(section, show: bool):
    section.footer.is_linked_to_previous = False
    ft = section.footer
    for p in ft.paragraphs:
        for r in list(p.runs):
            r._element.getparent().remove(r._element)
    p = ft.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    if show:
        fld_simple(p, "PAGE")
    section.header.is_linked_to_previous = False


def shade(cell, hex_fill="D9D9D9"):
    tcPr = cell._element.get_or_add_tcPr()
    sh = OxmlElement("w:shd")
    sh.set(qn("w:val"), "clear"); sh.set(qn("w:color"), "auto"); sh.set(qn("w:fill"), hex_fill)
    tcPr.append(sh)


def repeat_header(row):
    trPr = row._tr.get_or_add_trPr()
    el = OxmlElement("w:tblHeader"); el.set(qn("w:val"), "true"); trPr.append(el)


def cant_split(row):
    trPr = row._tr.get_or_add_trPr()
    el = OxmlElement("w:cantSplit"); el.set(qn("w:val"), "true"); trPr.append(el)


# ----------------------------------------------------------------------------------- booktabs tables
NUMERIC = re.compile(r"^[~<>\u2264\u2265]?[-+]?[\d.,]+( ?(%|ms|s|req/s|x))?( ?\[[\d., ]+\])?$|^[\d.,]+ ?/ ?[\d.,]+( ?/ ?[\d.,]+)?$|^-$")


def _border(parent, tag, sz, color="000000", val="single"):
    e = OxmlElement(f"w:{tag}")
    e.set(qn("w:val"), val)
    if val != "nil":
        e.set(qn("w:sz"), str(sz)); e.set(qn("w:space"), "0"); e.set(qn("w:color"), color)
    parent.append(e)


def booktabs(table, header_rows=1, light_rules=False):
    """Academic table style: 1.5 pt rule above the header, 0.75 pt below it, 1.5 pt at the bottom,
    no vertical lines; optional 0.25 pt light-grey separators for long tables; 4 pt cell padding."""
    tblPr = table._tbl.tblPr
    for old in tblPr.findall(qn("w:tblBorders")) + tblPr.findall(qn("w:tblCellMar")):
        tblPr.remove(old)
    bd = OxmlElement("w:tblBorders")
    _border(bd, "top", 12)
    _border(bd, "left", 0, val="nil")
    _border(bd, "bottom", 12)
    _border(bd, "right", 0, val="nil")
    if light_rules:
        _border(bd, "insideH", 2, color="BFBFBF")
    else:
        _border(bd, "insideH", 0, val="nil")
    _border(bd, "insideV", 0, val="nil")
    mar = OxmlElement("w:tblCellMar")
    for side, w in (("top", 80), ("left", 90), ("bottom", 80), ("right", 90)):
        e = OxmlElement(f"w:{side}"); e.set(qn("w:w"), str(w)); e.set(qn("w:type"), "dxa"); mar.append(e)
    # schema order: ... jc, tblInd, tblBorders, shd, tblLayout, tblCellMar, tblLook ...
    layout, look = tblPr.find(qn("w:tblLayout")), tblPr.find(qn("w:tblLook"))
    anchor = layout if layout is not None else look
    if anchor is not None:
        anchor.addprevious(bd)
    else:
        tblPr.append(bd)
    if look is not None:
        look.addprevious(mar)
    else:
        tblPr.append(mar)
    for ri in range(header_rows):
        for cell in table.rows[ri].cells:
            tcPr = cell._element.get_or_add_tcPr()
            tb = OxmlElement("w:tcBorders")
            _border(tb, "bottom", 6)
            tcPr.append(tb)
            shade(cell, "F2F2F2")


# ----------------------------------------------------------------------------------- builder
class Builder:
    def __init__(self, pages: dict | None):
        self.pages = pages or {}
        self.doc = Document()
        self.refs_num, self.ref_texts = load_refs()
        self.blocks = load_content()
        self.xref = number(self.blocks)
        self.front = tomllib.loads(S((CONTENT / "00_front.toml").read_text(encoding="utf-8")))
        self.abbr = tomllib.loads((CONTENT / "abbreviations.toml").read_text(encoding="utf-8"))["abbr"]
        self.toc_entries: list[tuple[int, str]] = []   # (level, text) in document order
        self.lot: list[str] = []
        self.lof: list[str] = []
        self.missing_refs: set[str] = set()
        self._styles()

    # -------------------------------------------------------------- styles
    def _styles(self):
        st = self.doc.styles
        style_fonts(st["Normal"], 12)
        pf = st["Normal"].paragraph_format
        pf.line_spacing = 1.5
        pf.space_after = Pt(2)
        for name, size, before, after in (("Heading 1", 16, 0, 12), ("Heading 2", 14, 8, 4), ("Heading 3", 12, 6, 3)):
            s = st[name]
            style_fonts(s, size, bold=True)
            s.font.italic = False
            s.paragraph_format.space_before = Pt(before)
            s.paragraph_format.space_after = Pt(after)
            s.paragraph_format.keep_with_next = True
            s.paragraph_format.line_spacing = 1.15
        st["Heading 1"].paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
        style_fonts(st["List Bullet"], 12)

    # -------------------------------------------------------------- text helpers
    def resolve(self, text: str) -> str:
        def xr(m):
            k = m.group(1)
            return self.xref.get(k, f"[MISSING {k}]")
        text = re.sub(r"\{((?:fig|tab):[a-z0-9_]+)\}", xr, text)

        def cite(m):
            keys = [k.strip().lstrip("@") for k in m.group(1).split(";")]
            nums = []
            for k in keys:
                if k in self.refs_num:
                    nums.append(self.refs_num[k])
                else:
                    self.missing_refs.add(k)
            return ", ".join(f"[{n}]" for n in sorted(nums))
        return re.sub(r"\[(@[^\]]+)\]", cite, text)

    def para(self, text, align=WD_ALIGN_PARAGRAPH.JUSTIFY, size=12, bold=False, after=2, before=0,
             keep_next=False, line=1.5, indent=None):
        p = self.doc.add_paragraph()
        pfmt(p, align=align, after=after, before=before, keep_next=keep_next, line=line, indent=indent)
        add_inline(p, self.resolve(text), size=size, base_bold=bold)
        return p

    def heading(self, text, level, toc_level=None, page_break_before=False, toc_text=None, align=None):
        p = self.doc.add_paragraph(style=f"Heading {level}")
        r = p.add_run(text)
        set_run_font(r, {1: 16, 2: 14, 3: 12}[level], bold=True)
        if page_break_before:
            p.paragraph_format.page_break_before = True
        if align is not None:
            p.alignment = align
        if toc_level is not None:
            self.toc_entries.append((toc_level, toc_text or text))
        return p

    def pg(self, kind, text):
        return self.pages.get((kind, text), "")

    # -------------------------------------------------------------- front pages
    def title_page(self, colour: bool):
        d = self.doc
        lines = [
            (S("A {REPORT_KIND}"), 14, False, 0), ("on", 12, False, 18),
            (S("{PROJECT_TITLE}"), 18, True, 18), ("by", 12, True, 18),
            (S("{STUDENT_NAME}"), 15, True, 0), (S("{ROLL_NUMBER}"), 15, True, 20),
            ("Under the Guidance of", 13, True, 10), (S("{GUIDE_NAME}"), 13, True, 0),
            (S("{GUIDE_DESIG},"), 13, True, 18), ("Submitted to", 13, True, 6),
        ]
        first = True
        for text, size, bold, after in lines:
            p = d.add_paragraph()
            pfmt(p, align=WD_ALIGN_PARAGRAPH.CENTER, after=after, line=1.15, before=12 if first else 0)
            first = False
            r = p.add_run(text)
            set_run_font(r, size, bold=bold, color=BLUE if (colour and text == SETTINGS["PROJECT_TITLE"]) else BLACK)
        logo = ASSETS / "pdeu-logo.png"
        p = d.add_paragraph()
        pfmt(p, align=WD_ALIGN_PARAGRAPH.CENTER, after=6, line=1.0)
        if logo.exists():
            p.add_run().add_picture(str(logo), height=Inches(1.4))
        else:  # reserved space for the university logo
            p.paragraph_format.space_before = Pt(0)
            p.paragraph_format.space_after = Pt(100)
        for text, size, after in ((S("{DEPARTMENT},"), 16, 0), ("School of Technology,", 16, 0),
                                  ("Pandit Deendayal Energy University", 16, 18), (S("{YEAR}"), 16, 0)):
            p = d.add_paragraph()
            pfmt(p, align=WD_ALIGN_PARAGRAPH.CENTER, after=after, line=1.15)
            set_run_font(p.add_run(text), size, bold=True)

    def certificate(self):
        d = self.doc
        p = d.add_paragraph(); pfmt(p, align=WD_ALIGN_PARAGRAPH.CENTER, after=24, line=1.15, before=12)
        r = p.add_run("CERTIFICATE"); set_run_font(r, 16, bold=True); r.font.underline = True
        text = S("This is to certify that the seminar report entitled “{PROJECT_TITLE},” submitted by "
                 "{STUDENT_NAME}, has been conducted under the supervision of {GUIDE_NAME}, {GUIDE_DESIG}, and is "
                 "hereby approved for the partial fulfillment of the requirements for the award of the degree of "
                 "{DEGREE} in the Department of {DEPARTMENT_SHORT} at Pandit Deendayal Energy University, "
                 "Gandhinagar. This work is original and has not been submitted to any other institution for the "
                 "award of any degree.")
        dep = SETTINGS["DEPARTMENT"]
        text = text.replace("{DEPARTMENT_SHORT}", dep[len("Department of "):] if dep.startswith("Department of ") else dep)
        p = d.add_paragraph(); pfmt(p, after=60, line=1.5, first=0.5)
        set_run_font(p.add_run(text), 12)
        for who, name in (("Guide", SETTINGS["GUIDE_NAME"]), ("Examiner", SETTINGS["EXAMINER_NAME"] or "")):
            block = ["Sign:", name if name else f"Name of {who}", SETTINGS["GUIDE_DESIG"] if who == "Guide" else "Designation",
                     "Department", "School of Technology", "Pandit Deendayal Energy University"]
            for i, t in enumerate(block):
                p = d.add_paragraph(); pfmt(p, align=WD_ALIGN_PARAGRAPH.LEFT, after=0, line=1.15)
                set_run_font(p.add_run(t), 12, bold=True)
            p = d.add_paragraph(); pfmt(p, after=48, line=1.0)

    def declaration(self):
        d = self.doc
        self.heading("DECLARATION", 1, toc_level=0, toc_text="Declaration")
        self.para(S("I hereby declare that the seminar report entitled “{PROJECT_TITLE}” is the result of "
                    "my own work and has been written by me."))
        self.para("[STUDENT TO COMPLETE: declaration wording about AI tool use, as approved by the guide]")
        self.para("This declaration is to affirm that the work presented in this report is genuinely conducted by me "
                  "and to the best of my knowledge, it is original.", after=18)
        for t in (S("{STUDENT_NAME}"), S("{ROLL_NUMBER}"), S("{DEPARTMENT}"), "School of Technology",
                  "Pandit Deendayal Energy University", "Gandhinagar"):
            self.para(t, align=WD_ALIGN_PARAGRAPH.LEFT, bold=True, after=0, line=1.15)
        self.para(S("Date: {DATE}"), align=WD_ALIGN_PARAGRAPH.LEFT, bold=True, before=12, after=0, line=1.15)
        self.para(S("Place: {PLACE}"), align=WD_ALIGN_PARAGRAPH.LEFT, bold=True, after=12, line=1.15)
        self.para("List of Tools Used for the Report with Purpose:", align=WD_ALIGN_PARAGRAPH.LEFT, bold=True, after=4)
        for t in self.front["tools"]:
            self.bullet(t)

    def acknowledgement(self):
        self.heading("ACKNOWLEDGEMENT", 1, toc_level=0, toc_text="Acknowledgement", page_break_before=True)
        for t in self.front["acknowledgement"]:
            self.para(t)
        self.para(S("{STUDENT_NAME}"), align=WD_ALIGN_PARAGRAPH.RIGHT, bold=True, before=24, after=0)
        self.para(S("{ROLL_NUMBER}"), align=WD_ALIGN_PARAGRAPH.RIGHT, bold=True, after=0)

    def abstract(self):
        self.heading("ABSTRACT", 1, toc_level=0, toc_text="Abstract", page_break_before=True)
        for t in self.front["abstract"]:
            self.para(t)

    def entry_line(self, text, page, indent=0.0, bold=False, label_tab=None):
        p = self.doc.add_paragraph()
        pfmt(p, align=WD_ALIGN_PARAGRAPH.LEFT, after=0, line=1.5, indent=indent)
        f = p.paragraph_format
        f.tab_stops.add_tab_stop(Inches(TEXT_W), WD_TAB_ALIGNMENT.RIGHT, WD_TAB_LEADER.DOTS)
        f.right_indent = Inches(0)
        if label_tab is not None:
            f.first_line_indent = Inches(-label_tab)
            f.left_indent = Inches(indent + label_tab)
        set_run_font(p.add_run(text), 12, bold=bold)
        set_run_font(p.add_run("\t" + (page or "00")), 12, bold=bold)
        return p

    def toc(self, entries):
        self.heading("TABLE OF CONTENTS", 1, page_break_before=True)
        first_p = None
        last_p = None
        for level, text in entries:
            page = self.pg("h", text)
            indent = {0: 0.0, 1: 0.35, 2: 0.7}[level]
            p = self.entry_line(text, page, indent=indent, bold=(level == 0 and not text.startswith(("Declaration", "Acknowledgement", "Abstract", "List of"))))
            if first_p is None:
                first_p = p
            last_p = p
        # Word TOC field around the static entries (Word: right-click > Update Field)
        if first_p is not None:
            begin_runs = []
            tmp = self.doc.add_paragraph()
            field_char(tmp, "begin", 'TOC \\o "1-2" \\h \\z \\u')
            for r in tmp._element.findall(qn("w:r")):
                begin_runs.append(r)
            ppr = first_p._element.find(qn("w:pPr"))
            idx = list(first_p._element).index(ppr) + 1 if ppr is not None else 0
            for k, r in enumerate(begin_runs):
                first_p._element.insert(idx + k, r)
            tmp._element.getparent().remove(tmp._element)
            end = OxmlElement("w:r"); fc = OxmlElement("w:fldChar"); fc.set(qn("w:fldCharType"), "end"); end.append(fc)
            last_p._element.append(end)

    def list_of(self, title, toc_text, items, kind):
        self.heading(title, 1, toc_level=0, toc_text=toc_text, page_break_before=True)
        for cap in items:
            self.entry_line(cap, self.pg(kind, cap), label_tab=1.05)

    def abbreviations(self):
        self.heading("LIST OF SYMBOLS, ABBREVIATIONS AND NOMENCLATURE", 1, toc_level=0,
                     toc_text="List of Symbols, Abbreviations and Nomenclature", page_break_before=True)
        items = sorted(self.abbr.items(), key=lambda kv: kv[0].lower().replace("_", ""))
        t = self.doc.add_table(rows=1, cols=2)
        t.alignment = WD_TABLE_ALIGNMENT.CENTER
        t.autofit = False
        w = [1.3, TEXT_W - 1.4]
        hdr = t.rows[0].cells
        for c, txt in zip(hdr, ("Abbreviation / symbol", "Meaning")):
            c.width = Inches(w[hdr.index(c)])
            p = c.paragraphs[0]; pfmt(p, align=WD_ALIGN_PARAGRAPH.LEFT, after=0, line=1.5)
            set_run_font(p.add_run(txt), 12, bold=True)
        for gc, wv in zip(t._tbl.tblGrid.findall(qn("w:gridCol")), w):
            gc.set(qn("w:w"), str(int(wv * 1440)))
        for k, v in items:
            row = t.add_row().cells
            for j, txt in enumerate((k, v)):
                row[j].width = Inches(w[j])
                p = row[j].paragraphs[0]; pfmt(p, align=WD_ALIGN_PARAGRAPH.LEFT, after=0, line=1.5)
                set_run_font(p.add_run(txt), 12, bold=(j == 0))
        repeat_header(t.rows[0])
        for r in t.rows:
            cant_split(r)
        booktabs(t, light_rules=True)

    # -------------------------------------------------------------- body blocks
    def bullet(self, text):
        p = self.doc.add_paragraph(style="List Bullet")
        pfmt(p, after=3, line=1.5, align=WD_ALIGN_PARAGRAPH.JUSTIFY)
        add_inline(p, self.resolve(text))

    def numbered(self, label, text):
        p = self.doc.add_paragraph()
        pfmt(p, after=3, line=1.5, indent=0.3, first=-0.3)
        p.paragraph_format.tab_stops.add_tab_stop(Inches(0.3))
        add_inline(p, f"{label}.\t" + self.resolve(text))

    def figure(self, b: Block):
        path = FIGS / b.file
        p = self.doc.add_paragraph()
        pfmt(p, align=WD_ALIGN_PARAGRAPH.CENTER, before=4, after=2, line=1.0, keep_next=True)
        p.add_run().add_picture(str(path), width=Inches(min(b.width, TEXT_W)))
        cap = f"Figure {b.label}: {b.text}"
        c = self.doc.add_paragraph()
        pfmt(c, align=WD_ALIGN_PARAGRAPH.CENTER, after=6, line=1.15)
        set_run_font(c.add_run(f"Figure {b.label}: "), 11, bold=True)
        set_run_font(c.add_run(b.text), 11)
        self.lof.append(cap)

    def table(self, b: Block, spacer: bool = True):
        cap = f"Table {b.label}: {b.text}"
        c = self.doc.add_paragraph()
        pfmt(c, align=WD_ALIGN_PARAGRAPH.CENTER, before=6, after=4, line=1.15, keep_next=True)
        set_run_font(c.add_run(f"Table {b.label}: "), 11, bold=True)
        set_run_font(c.add_run(self.resolve(b.text)), 11)
        self.lot.append(cap)
        ncol = len(b.rows[0])
        t = self.doc.add_table(rows=0, cols=ncol)
        t.alignment = WD_TABLE_ALIGNMENT.CENTER
        t.autofit = False
        ws = b.widths or [100 / ncol] * ncol
        tot = sum(ws)
        widths = [TEXT_W * w / tot for w in ws]
        nrows = len(b.rows)
        numcols = {j for j in range(1, ncol)
                   if nrows > 1 and all(NUMERIC.match((r[j] if j < len(r) else "").replace("**", "").strip()) for r in b.rows[1:])}
        for ri, row in enumerate(b.rows):
            cells = t.add_row().cells
            cant_split(t.rows[ri])
            if ri == 0:
                repeat_header(t.rows[ri])
            for j in range(ncol):
                txt = row[j] if j < len(row) else ""
                cell = cells[j]
                cell.width = Inches(widths[j])
                p = cell.paragraphs[0]
                align = WD_ALIGN_PARAGRAPH.RIGHT if j in numcols else WD_ALIGN_PARAGRAPH.LEFT
                pfmt(p, align=align, after=0, line=1.0, keep_next=(ri < nrows - 1 and nrows < 12))
                add_inline(p, self.resolve(txt), size=11 if ri == 0 else 10.5, base_bold=(ri == 0), mono_size=10)
        for gc, w in zip(t._tbl.tblGrid.findall(qn("w:gridCol")), widths):
            gc.set(qn("w:w"), str(int(w * 1440)))
        booktabs(t, light_rules=nrows > 8)
        if spacer:
            sp = self.doc.add_paragraph(); pfmt(sp, after=0, line=1.0)
            set_run_font(sp.add_run(""), 6)
            sp.paragraph_format.line_spacing = Pt(6)

    def code(self, b: Block, spacer: bool = True):
        for k, ln in enumerate(b.lines):
            p = self.doc.add_paragraph()
            pfmt(p, align=WD_ALIGN_PARAGRAPH.LEFT, after=0, line=1.0, indent=0.15,
                 keep_next=k < len(b.lines) - 1)
            set_run_font(p.add_run(ln.replace(" ", " ")), 8.5, font=MONO)
        if spacer:
            sp = self.doc.add_paragraph(); pfmt(sp, after=4, line=1.0)

    # -------------------------------------------------------------- toc pre-scan
    def body_toc(self):
        out = []
        for b in self.blocks:
            if b.kind == "chapter":
                out.append((0, f"{b.label}: {b.text}"))
            elif b.kind == "part":
                out.append((0, b.text))
            elif b.kind == "section":
                out.append((1, f"{b.label} {b.text}"))
            elif b.kind == "usection":
                out.append((1, b.text))
        out.append((0, "References"))
        return out

    def captions(self, kind):
        res = []
        for b in self.blocks:
            if b.kind == kind:
                res.append(f"{'Figure' if kind == 'figure' else 'Table'} {b.label}: {self.resolve(b.text)}")
        return res

    # -------------------------------------------------------------- build
    def build(self):
        d = self.doc
        s1 = d.sections[0]
        set_section(s1)
        footer_page_number(s1, show=False)
        self.title_page(colour=True)                 # 1 cover (colour accent on the title only)
        page_break(d)
        self.title_page(colour=False)                # 2 title page (black and white)
        page_break(d)
        self.certificate()                           # 3 certificate

        s2 = d.add_section(WD_SECTION.NEW_PAGE)      # front matter: roman numerals from i
        set_section(s2, "lowerRoman", 1)
        footer_page_number(s2, show=True)
        self.declaration()
        self.acknowledgement()
        self.abstract()
        front_entries = [(0, "Declaration"), (0, "Acknowledgement"), (0, "Abstract"), (0, "List of Tables"),
                         (0, "List of Figures"), (0, "List of Symbols, Abbreviations and Nomenclature")]
        self.toc(front_entries + self.body_toc())
        self.list_of("LIST OF TABLES", "List of Tables", self.captions("table"), "t")
        self.list_of("LIST OF FIGURES", "List of Figures", self.captions("figure"), "f")
        self.abbreviations()

        s3 = d.add_section(WD_SECTION.NEW_PAGE)      # main text: arabic from 1
        set_section(s3, "decimal", 1)
        footer_page_number(s3, show=True)
        first_chapter = True
        for bi, b in enumerate(self.blocks):
            nxt = self.blocks[bi + 1].kind if bi + 1 < len(self.blocks) else "chapter"
            spacer = nxt not in ("chapter", "part")
            if b.kind == "chapter":
                self.heading(f"{b.label}: {b.text}", 1, page_break_before=not first_chapter)
                first_chapter = False
            elif b.kind == "part":
                self.heading(b.text, 1, page_break_before=True)
            elif b.kind == "section":
                self.heading(f"{b.label} {b.text}", 2)
            elif b.kind == "usection":
                self.heading(b.text, 2)
            elif b.kind == "para":
                self.para(b.text)
            elif b.kind == "bullet":
                self.bullet(b.text)
            elif b.kind == "number":
                self.numbered(b.label, b.text)
            elif b.kind == "figure":
                self.figure(b)
            elif b.kind == "table":
                self.table(b, spacer)
            elif b.kind == "code":
                self.code(b, spacer)
        # references: alphabetical, single-spaced, left-aligned
        self.heading("References", 1, page_break_before=True)
        for i, t in enumerate(self.ref_texts, 1):
            p = d.add_paragraph()
            pfmt(p, align=WD_ALIGN_PARAGRAPH.LEFT, after=2, line=1.0, indent=0.42, first=-0.42)
            p.paragraph_format.tab_stops.add_tab_stop(Inches(0.42))
            add_inline(p, f"[{i}]\t" + t, size=12)
        zoom = d.settings.element.find(qn("w:zoom"))
        if zoom is not None and zoom.get(qn("w:percent")) is None:
            zoom.set(qn("w:percent"), "100")
        d.core_properties.title = SETTINGS["PROJECT_TITLE"]
        d.core_properties.author = SETTINGS["STUDENT_NAME"]
        d.save(OUT_DOCX)
        return self


# ----------------------------------------------------------------------------------- pagination
TNR_DIR = Path("/System/Library/Fonts/Supplemental")


def to_pdf(docx: Path) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="agw-report-"))
    # Private LibreOffice profile whose user font folder holds the system Times New Roman, so the PDF
    # uses the real font instead of a metric-compatible substitute.
    prof = tmp / "profile"
    fonts = prof / "user" / "fonts"
    fonts.mkdir(parents=True)
    for f in [*TNR_DIR.glob("Times New Roman*.ttf"), *TNR_DIR.glob("Courier New*.ttf")]:
        shutil.copy(f, fonts / f.name)
    subprocess.run(["soffice", f"-env:UserInstallation=file://{prof}", "--headless", "--convert-to", "pdf",
                    "--outdir", str(tmp), str(docx)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return tmp / (docx.stem + ".pdf")


def pdf_pages(pdf: Path) -> list[list[str]]:
    txt = subprocess.run(["pdftotext", "-layout", str(pdf), "-"], check=True, capture_output=True, text=True).stdout
    return [[re.sub(r"\s+", " ", ln).strip() for ln in pg.splitlines() if ln.strip()] for pg in txt.split("\f")]


def norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.replace("’", "'").replace("–", "-")).strip().lower()


def roman(n: int) -> str:
    vals = [(10, "x"), (9, "ix"), (5, "v"), (4, "iv"), (1, "i")]
    out = ""
    for v, r in vals:
        while n >= v:
            out += r; n -= v
    return out


def locate(builder: Builder, pdf: Path):
    pages = pdf_pages(pdf)
    def is_leader(line):
        return bool(re.search(r"\.{4,}|\s\d+$|\s[ivx]+$", line))

    def find(text, start, kind):
        key = norm(text)[:32]
        for i in range(start, len(pages)):
            for ln in pages[i]:
                n = norm(ln)
                if n.startswith(key) and not re.search(r"\.{4,}", ln):
                    return i
        return None

    # physical page indexes
    decl = find("DECLARATION", 0, "h")
    main = None
    for i, pg in enumerate(pages):
        if pg and norm(pg[0]).startswith("chapter 1: introduction"):
            main = i; break
    if decl is None or main is None:
        raise SystemExit(f"cannot locate sections (declaration={decl}, main={main})")
    result = {}
    cur = decl
    front = ["Declaration", "Acknowledgement", "Abstract", "List of Tables", "List of Figures",
             "List of Symbols, Abbreviations and Nomenclature"]
    for t in front:
        i = find(t.upper() if t != "Declaration" else "DECLARATION", cur, "h")
        result[("h", t)] = roman(i - decl + 1); cur = i
    cur = main
    for level, text in builder.body_toc():
        probe = text.upper() if False else text
        i = find(probe, cur, "h")
        if i is None:
            raise SystemExit(f"heading not found in PDF: {text}")
        result[("h", text)] = str(i - main + 1); cur = i
    for kind, items in (("t", builder.lot), ("f", builder.lof)):
        cur = main
        for cap in items:
            i = find(cap, main, kind)
            if i is None:
                raise SystemExit(f"caption not found in PDF: {cap}")
            result[(kind, cap)] = str(i - main + 1)
    stats = {"physical": len([p for p in pages if p]), "front_first": decl, "main_first": main,
             "front_pages": main - decl, "main_pages": len([p for p in pages if p]) - main}
    return result, stats, pages


def main():
    for f in ("fig3_1_architecture.png", "fig5_1_rq1_latency.png"):
        if not (FIGS / f).exists():
            raise SystemExit("run figures/make_figures.py first")
    pages = None
    stats = None
    for it in range(6):
        b = Builder(pages).build()
        if b.missing_refs:
            raise SystemExit(f"unknown citation keys: {sorted(b.missing_refs)}")
        pdf = to_pdf(OUT_DOCX)
        new, stats, _ = locate(b, pdf)
        print(f"pass {it + 1}: front {stats['front_pages']} pages, main {stats['main_pages']} pages")
        if new == pages:
            shutil.copy(pdf, OUT_PDF)
            break
        pages = new
    else:
        shutil.copy(pdf, OUT_PDF)
        print("warning: page numbers did not stabilise", file=sys.stderr)
    print(f"wrote {OUT_DOCX.relative_to(HERE.parents[1])} and {OUT_PDF.relative_to(HERE.parents[1])}")
    print(stats)


if __name__ == "__main__":
    main()
