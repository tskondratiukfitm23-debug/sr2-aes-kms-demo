"""CLI демо-застосунку AES-KMS.

Команди: key new|rotate|list|disable|migrate, enc, dec, info, tamper, nonce-test.
Пароль: --password, змінна AKMS_PASSWORD або інтерактивний запит (getpass) — рекомендовано.
"""
import argparse
import getpass
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from kms.aes_kms import (AKMSError, KeyStore, NonceReuseError, decrypt_file, encrypt,  # noqa: E402
                         encrypt_file, migrate_file, parse_container, ContainerError)

DEFAULT_KS = os.environ.get("AKMS_KEYSTORE", os.path.join(ROOT, "kms", "keystore.json"))


def password(args) -> str:
    if getattr(args, "password", None):
        return args.password
    if os.environ.get("AKMS_PASSWORD"):
        return os.environ["AKMS_PASSWORD"]
    return getpass.getpass("Master-пароль: ")


def ok(msg):
    print(f"[OK] {msg}")


def cmd_key(args):
    ks = KeyStore(args.keystore)
    if args.action == "new":
        ok(f"Створено ключ AES-256, зашифрований KEK (PBKDF2 {ks.db['kdf']['iters']} іт.): "
           f"{ks.new_key(args.label, password(args), args.max_uses)}")
    elif args.action == "rotate":
        meta = ks.rotate(args.label, password(args), args.max_uses)
        ok(f"Ротація: новий активний ключ {meta.key_id} (v{meta.version}); попередній -> retiring")
    elif args.action == "list":
        print(f"KDF: {ks.db['kdf']['name']}, ітерацій={ks.db['kdf']['iters']}, сіль={ks.db['kdf']['salt_bytes']} Б; "
              f"політика: max_uses={ks.db['policy']['max_uses']}, max_age_days={ks.db['policy']['max_age_days']}")
        print(f"{'KEY_ID':<17}{'LABEL':<10}{'VER':<5}{'ALG':<9}{'STATE':<10}{'USES':<14}CREATED")
        for m in ks.list(args.label):
            print(f"{m.key_id:<17}{m.label:<10}{m.version:<5}{m.alg:<9}{m.state:<10}"
                  f"{f'{m.uses}/{m.max_uses}':<14}{m.created}")
    elif args.action == "disable":
        ok(f"Ключ виведено з обігу: {ks.disable(args.key_id)}")
    elif args.action == "migrate":
        pw = password(args)
        for p in args.infiles:
            old, new = migrate_file(ks, p, args.label, pw)
            ok(f"{os.path.basename(p)}: перешифровано {old} -> {new}")


def cmd_enc(args):
    ks = KeyStore(args.keystore)
    h = encrypt_file(ks, args.infile, args.outfile, args.label, password(args), args.mode, args.aad)
    ok(f"Зашифровано {args.infile} -> {args.outfile} ({h['alg']}, key_id={h['key_id']}, "
       f"{'nonce' if h['mode'] == 'GCM' else 'iv'}={h.get('nonce') or h.get('iv')}, aad='{h['aad']}')")


def cmd_dec(args):
    ks = KeyStore(args.keystore)
    h = decrypt_file(ks, args.infile, args.outfile, password(args), args.aad)
    ok(f"Розшифровано {args.infile} -> {args.outfile} ({h['mode']}, key_id={h['key_id']}); тег/MAC перевірено")


def cmd_info(args):
    with open(args.infile, "rb") as f:
        blob = f.read()
    h, hb, body = parse_container(blob)
    tail = 16 if h["mode"] == "GCM" else 32
    print(json.dumps(h, ensure_ascii=False, indent=2))
    print(f"Структура: MAGIC+ver+len={7} Б | header={len(hb) - 7} Б | ciphertext={len(body) - tail} Б | "
          f"{'tag' if h['mode'] == 'GCM' else 'HMAC'}={tail} Б | всього={len(blob)} Б")


def cmd_tamper(args):
    with open(args.infile, "rb") as f:
        b = bytearray(f.read())
    h, hb, body = parse_container(bytes(b))
    tail = 16 if h["mode"] == "GCM" else 32
    pos = {"ct": len(hb) + (len(body) - tail) // 2, "tag": len(b) - 1,
           "header": hb.index(b'"created"') + 14}[args.region]
    b[pos] ^= 0x01
    out = args.outfile or args.infile
    with open(out, "wb") as f:
        f.write(b)
    ok(f"Змінено 1 біт у байті #{pos} (область: {args.region}) -> {out}")


def cmd_nonce(args):
    ks = KeyStore(args.keystore)
    pw = password(args)
    fixed = bytes(12)
    encrypt(ks, b"message-1", args.label, pw, "gcm", "nonce-test", _force_iv=fixed)
    ok("1-ше шифрування з nonce=000000000000000000000000 — дозволено")
    try:
        encrypt(ks, b"message-2", args.label, pw, "gcm", "nonce-test", _force_iv=fixed)
        print("[ПОМИЛКА] повторний nonce прийнято!")
        sys.exit(1)
    except NonceReuseError as e:
        print(f"[ВІДМОВА] 2-ге шифрування з тим самим nonce: {e}")


def build_parser():
    ap = argparse.ArgumentParser(prog="cli.py", description="AES-KMS демо (AES-GCM / AES-CBC+HMAC, ротація ключів)")
    ap.add_argument("--keystore", default=DEFAULT_KS)
    sp = ap.add_subparsers(dest="cmd", required=True)

    def pw(p):
        p.add_argument("--password", help="краще AKMS_PASSWORD або інтерактивний ввід")

    pk = sp.add_parser("key")
    sk = pk.add_subparsers(dest="action", required=True)
    p = sk.add_parser("list"); p.add_argument("--label")
    for name in ("new", "rotate"):
        p = sk.add_parser(name); p.add_argument("--label", required=True); p.add_argument("--max-uses", type=int); pw(p)
    p = sk.add_parser("disable"); p.add_argument("--key-id", required=True)
    p = sk.add_parser("migrate"); p.add_argument("--label", required=True)
    p.add_argument("--in", dest="infiles", nargs="+", required=True); pw(p)

    p = sp.add_parser("enc"); p.add_argument("--in", dest="infile", required=True)
    p.add_argument("--out", dest="outfile", required=True)
    p.add_argument("--mode", choices=["gcm", "cbc"], default="gcm")
    p.add_argument("--label", required=True); p.add_argument("--aad"); pw(p)

    p = sp.add_parser("dec"); p.add_argument("--in", dest="infile", required=True)
    p.add_argument("--out", dest="outfile", required=True); p.add_argument("--aad"); pw(p)

    p = sp.add_parser("info"); p.add_argument("--in", dest="infile", required=True)
    p = sp.add_parser("tamper"); p.add_argument("--in", dest="infile", required=True)
    p.add_argument("--out", dest="outfile"); p.add_argument("--region", choices=["ct", "tag", "header"], default="ct")
    p = sp.add_parser("nonce-test"); p.add_argument("--label", required=True); pw(p)
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        {"key": cmd_key, "enc": cmd_enc, "dec": cmd_dec, "info": cmd_info,
         "tamper": cmd_tamper, "nonce-test": cmd_nonce}[args.cmd](args)
    except ContainerError as e:
        print(f"[ВІДМОВА] {e}", file=sys.stderr)       # уніфіковано, без деталей
        return e.code
    except AKMSError as e:
        print(f"[ВІДМОВА] {e}", file=sys.stderr)
        return e.code
    except FileNotFoundError as e:
        print(f"[ВІДМОВА] файл не знайдено: {e.filename}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
