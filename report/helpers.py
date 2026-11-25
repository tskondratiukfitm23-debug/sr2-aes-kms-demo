"""Спільна частина: шаблон ЛР3 (титулка, стилі) і хелпери."""
import ast, json, os

import docx
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt
from PIL import Image

HOME = "/home/ubuntu"
PRJ = f"{HOME}/sr2"
SHOTS = f"{HOME}/sr2/docs/screenshots"
WORK = f"{HOME}/sr2_report"
SRC = f"{HOME}/Кондратюк_ЛР3_Прикладні_аспекти.docx"
OUT = f"{HOME}/Кондратюк_СР2_Модуль_шифрування_AES.docx"
REPO = "https://github.com/tskondratiukfitm23-debug/sr2-aes-kms-demo"

# ---------------------------------------------------------------- шаблон
d = docx.Document(SRC)
body = d.element.body
paras = d.paragraphs
paras[7].runs[0].text = "з самостійної роботи №2"
for r in paras[7].runs[1:]:
    r.text = ""
paras[11].runs[0].text = "Тема: «Створення безпечного модуля шифрування та управління ключами AES»"
for r in paras[11].runs[1:]:
    r.text = ""
zmist = paras[20]._p
sect = body[-1]
started = False
for el in list(body):
    if el is zmist:
        started = True
        continue
    if started and el is not sect:
        body.remove(el)

TOC_FILE = f"{WORK}/toc.json"
TOC = json.load(open(TOC_FILE, encoding="utf-8")) if os.path.exists(TOC_FILE) else []
anchor = zmist
for level, text, page in TOC:
    tp = OxmlElement("w:p")
    pPr = OxmlElement("w:pPr")
    ps = OxmlElement("w:pStyle"); ps.set(qn("w:val"), "TOC1" if level == 1 else "TOC2"); pPr.append(ps)
    tabs = OxmlElement("w:tabs"); tab = OxmlElement("w:tab")
    tab.set(qn("w:val"), "right"); tab.set(qn("w:pos"), "9354"); tab.set(qn("w:leader"), "dot")
    tabs.append(tab); pPr.append(tabs); tp.append(pPr)
    rr = OxmlElement("w:r")
    t1 = OxmlElement("w:t"); t1.text = text; t1.set(qn("xml:space"), "preserve"); rr.append(t1)
    rr.append(OxmlElement("w:tab"))
    t2 = OxmlElement("w:t"); t2.text = str(page); rr.append(t2)
    tp.append(rr)
    anchor.addnext(tp); anchor = tp


# ---------------------------------------------------------------- хелпери
def page_break():
    d.add_paragraph(style="Normal").add_run().add_break(WD_BREAK.PAGE)


def H1(text, new_page=True):
    para = d.add_paragraph(text, style="Heading 1")
    para.paragraph_format.page_break_before = new_page   # без порожніх сторінок


def H2(text):
    d.add_paragraph(text, style="Heading 2")


def P(text, bold_prefix=None):
    para = d.add_paragraph(style="Normal")
    para.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    if bold_prefix:
        para.add_run(bold_prefix).bold = True
    para.add_run(text)
    return para


def B(text, bold_prefix=None):
    para = d.add_paragraph(style="List Bullet")
    para.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    if bold_prefix:
        para.add_run(bold_prefix).bold = True
    para.add_run(text)


def CODE(text):
    for line in text.rstrip("\n").split("\n"):
        d.add_paragraph(line if line else " ", style="Code Block")


def CAP(text, center=False):
    para = d.add_paragraph(text, style="Caption UA")
    if center:
        para.alignment = WD_ALIGN_PARAGRAPH.CENTER


TAB_N, FIG_N = [0], [0]


def shade(cell, fill="D9D9D9"):
    tcPr = cell._tc.get_or_add_tcPr()
    s = OxmlElement("w:shd"); s.set(qn("w:val"), "clear"); s.set(qn("w:fill"), fill); tcPr.append(s)


def TABLE(caption, header, rows, widths=None, size=10):
    TAB_N[0] += 1
    CAP(f"Таблиця {TAB_N[0]} — {caption}")
    tb = d.add_table(rows=1 + len(rows), cols=len(header))
    tb.style = d.styles["Table Grid"]
    tb.alignment = 1
    for ri, row in enumerate([header] + rows):
        for ci, val in enumerate(row):
            c = tb.cell(ri, ci)
            c.text = ""
            para = c.paragraphs[0]
            pf = para.paragraph_format
            pf.first_line_indent = Cm(0); pf.left_indent = Cm(0)
            pf.space_before = Pt(1); pf.space_after = Pt(1); pf.line_spacing = 1.0
            para.alignment = WD_ALIGN_PARAGRAPH.CENTER if ri == 0 else WD_ALIGN_PARAGRAPH.LEFT
            run = para.add_run(str(val))
            run.font.size = Pt(size)
            if ri == 0:
                run.bold = True
                shade(c)
    if widths:
        tb.autofit = False
        grid = tb._tbl.tblGrid
        for gc, w in zip(grid.findall(qn("w:gridCol")), widths):
            gc.set(qn("w:w"), str(int(w * 567)))
        for ci, w in enumerate(widths):
            tb.columns[ci].width = Cm(w)
        for ri in range(len(rows) + 1):
            for ci, w in enumerate(widths):
                tb.cell(ri, ci).width = Cm(w)
    d.add_paragraph(style="Normal")
    return TAB_N[0]


def FIG(path, caption, width=None):
    assert os.path.exists(path), path
    if width is None:
        with Image.open(path) as im:
            width = min(16.5, im.width / 90)
    FIG_N[0] += 1
    para = d.add_paragraph(style="Normal")
    para.alignment = WD_ALIGN_PARAGRAPH.CENTER
    para.paragraph_format.first_line_indent = Cm(0)
    para.add_run().add_picture(path, width=Cm(width))
    CAP(f"Рисунок {FIG_N[0]} — {caption}", center=True)
    return FIG_N[0]


def CROP(name, box, out_name):
    dst = os.path.join(WORK, "crop", out_name)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    with Image.open(os.path.join(SHOTS, name)) as im:
        w, h = im.size
        x0, y0, x1, y1 = box
        im.crop((int(x0 * w), int(y0 * h), int(x1 * w), int(y1 * h))).save(dst)
    return dst
