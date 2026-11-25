"""Тест на реальних файлах: шифрування/розшифрування через CLI-API, перевірка SHA-256,
накладні витрати контейнера та швидкість. Результат: outputs/real_data_results.json."""
import hashlib
import json
import os
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from kms.aes_kms import KeyStore, decrypt_file, encrypt_file  # noqa: E402

PW = "S3cure-Master-Pass!"
FILES = [
    ("Текст (UTF-8)", os.path.join(ROOT, "data", "sample.txt")),
    ("Текст ліцензії GPL-3", "/usr/share/common-licenses/GPL-3"),
    ("Зображення JPEG", "/usr/share/texlive/texmf-dist/tex/latex/beamer2thesis/logopolito.jpg"),
    ("Документ PDF", "/usr/share/texlive/texmf-dist/tex/latex/duckuments/example-image-duck.pdf"),
    ("Документ DOCX (звіт СР1)", os.path.expanduser("~/Кондратюк_СР1_Комплексний_аудит_OWASP.docx")),
    ("Бінарний файл .so (19 МБ)", "/usr/lib/libreoffice/program/libswlo.so"),
    ("Бінарний файл .so (82 МБ)", "/usr/lib/libreoffice/program/libmergedlo.so"),
]


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def human(n):
    for u in ("Б", "КБ", "МБ"):
        if n < 1024 or u == "МБ":
            return f"{n:.0f} {u}" if u == "Б" else f"{n:.1f} {u}"
        n /= 1024


tmp = tempfile.mkdtemp()
ks = KeyStore(os.path.join(tmp, "ks.json"))
ks.new_key("real", PW)
res = []
for kind, path in FILES:
    if not os.path.exists(path):
        continue
    for mode in ("gcm", "cbc"):
        out, back = os.path.join(tmp, "f." + mode), os.path.join(tmp, "f.dec")
        size = os.path.getsize(path)
        t0 = time.perf_counter(); encrypt_file(ks, path, out, "real", PW, mode); t1 = time.perf_counter()
        decrypt_file(ks, out, back, PW); t2 = time.perf_counter()
        same = sha(path) == sha(back)
        res.append({"type": kind, "file": os.path.basename(path), "mode": mode.upper(), "size": size,
                    "enc_size": os.path.getsize(out), "overhead": os.path.getsize(out) - size,
                    "enc_ms": round((t1 - t0) * 1000, 1), "dec_ms": round((t2 - t1) * 1000, 1),
                    "sha256_equal": same})

print(f"{'Тип даних':<27}{'Режим':<6}{'Розмір':>10}{'Контейнер':>11}{'+Б':>6}{'enc, мс':>9}{'dec, мс':>9}  SHA-256 збіг")
print("-" * 92)
for r in res:
    print(f"{r['type']:<27}{r['mode']:<6}{human(r['size']):>10}{human(r['enc_size']):>11}{r['overhead']:>6}"
          f"{r['enc_ms']:>9}{r['dec_ms']:>9}  {'так' if r['sha256_equal'] else 'НІ'}")
print("-" * 92)
print(f"Файлів: {len(res) // 2}, операцій round-trip: {len(res)}, усі SHA-256 збіглися: "
      f"{'ТАК' if all(r['sha256_equal'] for r in res) else 'НІ'}")
os.makedirs(os.path.join(ROOT, "outputs"), exist_ok=True)
json.dump(res, open(os.path.join(ROOT, "outputs", "real_data_results.json"), "w", encoding="utf-8"),
          ensure_ascii=False, indent=2)
