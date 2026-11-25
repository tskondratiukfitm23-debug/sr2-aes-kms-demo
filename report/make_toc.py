import json, re, docx, pymupdf
D = "/home/ubuntu/Кондратюк_СР2_Модуль_шифрування_AES.docx"
P = "/home/ubuntu/.tmp/Кондратюк_СР2_Модуль_шифрування_AES.pdf"
heads = [(1 if p.style.name == "Heading 1" else 2, p.text)
         for p in docx.Document(D).paragraphs if p.style.name in ("Heading 1", "Heading 2")]
pdf = pymupdf.open(P)
norm = lambda x: re.sub(r"\s+", " ", x).strip()
texts = [norm(pg.get_text()) for pg in pdf]
out = []; start = 2
for lvl, h in heads:
    key = norm(h)[:45]
    for i in range(start, len(texts)):
        if key in texts[i]:
            out.append([lvl, h, i + 1]); start = i; break
    else:
        print("NOT FOUND", h)
json.dump(out, open("/home/ubuntu/sr2_report/toc.json", "w", encoding="utf-8"), ensure_ascii=False)
print("heads", len(heads), "matched", len(out))
