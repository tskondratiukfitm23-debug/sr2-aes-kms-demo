"""«Захищений нотатник» — простий застосунок, у який інтегровано модуль AES-KMS.

Кожна нотатка — окремий контейнер AES-256-GCM у data/vault/<id>.akms.
AAD = "vault:note:<id>" прив'язує шифртекст до конкретної нотатки
(підміна/перестановка файлів між нотатками виявляється як дефект контейнера).

  python app/vault.py add --title "Wi-Fi" --text "пароль від роутера ..."
  python app/vault.py list
  python app/vault.py show --id 1
"""
import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from kms.aes_kms import AKMSError, KeyStore, decrypt, encrypt, parse_container  # noqa: E402

LABEL = "vault"


class Vault:
    def __init__(self, ks: KeyStore, folder: str):
        self.ks, self.folder = ks, folder
        os.makedirs(folder, exist_ok=True)

    def _path(self, nid: int) -> str:
        return os.path.join(self.folder, f"{nid}.akms")

    def ids(self) -> list:
        return sorted(int(f[:-5]) for f in os.listdir(self.folder) if f.endswith(".akms"))

    def add(self, title: str, text: str, password: str) -> int:
        if not any(m.state == "active" for m in self.ks.list(LABEL)):
            self.ks.new_key(LABEL, password)
        nid = (self.ids() or [0])[-1] + 1
        payload = json.dumps({"title": title, "text": text}, ensure_ascii=False).encode()
        with open(self._path(nid), "wb") as f:
            f.write(encrypt(self.ks, payload, LABEL, password, "gcm", f"vault:note:{nid}"))
        return nid

    def show(self, nid: int, password: str) -> dict:
        with open(self._path(nid), "rb") as f:
            _, pt = decrypt(self.ks, f.read(), password, expect_aad=f"vault:note:{nid}")
        return json.loads(pt)

    def listing(self) -> list:
        out = []
        for nid in self.ids():
            with open(self._path(nid), "rb") as f:
                h = parse_container(f.read())[0]        # заголовок відкритий, вміст — ні
            out.append((nid, h["key_id"], h["created"]))
        return out


def main(argv=None):
    from app.cli import DEFAULT_KS, password
    ap = argparse.ArgumentParser(prog="vault.py", description="Захищений нотатник на AES-KMS")
    ap.add_argument("--keystore", default=DEFAULT_KS)
    ap.add_argument("--dir", default=os.path.join(ROOT, "data", "vault"))
    ap.add_argument("--password")
    sp = ap.add_subparsers(dest="cmd", required=True)
    p = sp.add_parser("add"); p.add_argument("--title", required=True); p.add_argument("--text", required=True)
    sp.add_parser("list")
    p = sp.add_parser("show"); p.add_argument("--id", type=int, required=True)
    a = ap.parse_args(argv)
    v = Vault(KeyStore(a.keystore), a.dir)
    try:
        if a.cmd == "add":
            print(f"[OK] Нотатку #{v.add(a.title, a.text, password(a))} збережено зашифрованою (AES-256-GCM)")
        elif a.cmd == "list":
            for nid, kid, created in v.listing():
                print(f"#{nid:<3} key_id={kid}  створено {created}  (вміст зашифровано)")
        else:
            n = v.show(a.id, password(a))
            print(f"#{a.id} «{n['title']}»: {n['text']}")
    except AKMSError as e:
        print(f"[ВІДМОВА] {e}", file=sys.stderr)
        return e.code
    return 0


if __name__ == "__main__":
    sys.exit(main())
