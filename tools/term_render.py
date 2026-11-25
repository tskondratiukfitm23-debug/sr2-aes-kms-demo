"""Запускає bash-скрипт і рендерить його вивід (з ANSI-кольорами) як знімок терміналу."""
import re
import subprocess
import sys
import textwrap

from PIL import Image, ImageDraw, ImageFont

script, out = sys.argv[1], sys.argv[2]
cols = int(sys.argv[3]) if len(sys.argv) > 3 else 150
txt = subprocess.run(["bash", script], capture_output=False, stdout=subprocess.PIPE,
                     stderr=subprocess.STDOUT, text=True, env={**__import__("os").environ, "COLUMNS": str(cols)}).stdout
FONT = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 13)
BOLD = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf", 13)
cw = FONT.getbbox("M")[2]; lh = 17
COL = {"32": (90, 220, 90), "34": (110, 150, 255), "31": (240, 90, 90), "33": (230, 200, 80), "0": (224, 224, 224)}
lines = []
for raw in txt.expandtabs(8).rstrip("\n").split("\n"):
    segs, style, pos = [], ("0", False), 0
    for m in re.finditer(r"\x1b\[([0-9;]*)m", raw):
        segs.append((raw[pos:m.start()], style)); pos = m.end()
        codes = m.group(1).split(";") if m.group(1) else ["0"]
        bold = "1" in codes; c = next((x for x in codes if x in COL and x != "0"), "0")
        style = (c, bold)
    segs.append((raw[pos:], style))
    # перенос довгих рядків
    cur, n = [], 0
    for s, st in segs:
        while s:
            take = s[: cols - n]; cur.append((take, st)); n += len(take); s = s[len(take):]
            if n >= cols:
                lines.append(cur); cur, n = [], 0
    lines.append(cur)
W = cols * cw + 20; H = len(lines) * lh + 16
im = Image.new("RGB", (W, H), (30, 30, 30)); d = ImageDraw.Draw(im)
for i, ln in enumerate(lines):
    x = 10
    for s, (c, b) in ln:
        color = COL[c]
        if c == "0" and s.startswith("[ВІДМОВА]"):
            color = (255, 120, 110)
        elif c == "0" and s.startswith("[OK]"):
            color = (150, 230, 150)
        d.text((x, 8 + i * lh), s, font=BOLD if b else FONT, fill=color); x += len(s) * cw
im.save(out); print(out, im.size)
