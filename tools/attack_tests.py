"""Перевірка стійкості модуля до атак: кожен сценарій має завершитися відмовою.
Результат: outputs/attack_results.json + таблиця в консолі."""
import base64
import json
import os
import secrets
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from kms.aes_kms import (AKMSError, BadPassword, ContainerError, KeyStore, NonceReuseError,  # noqa: E402
                         WeakKdfError, decrypt, encrypt, pack_header, parse_container, seal)

PW = "S3cure-Master-Pass!"
tmp = tempfile.mkdtemp()
ks = KeyStore(os.path.join(tmp, "ks.json"))
ks.new_key("demo", PW)
MSG = b"0123456789ABCDEF" + b"amount=100;to=al" + b"ice;note=salary.."


def flip(blob, pos):
    b = bytearray(blob); b[pos] ^= 1; return bytes(b)


def body_off(blob):
    return len(parse_container(blob)[1])


def scen_gcm(mode):
    c = encrypt(ks, MSG, "demo", PW, mode, aad="doc=1")
    h, hb, body = parse_container(c)
    f = "nonce" if mode == "gcm" else "iv"
    hn = dict(h); raw = bytearray(base64.b64decode(h[f])); raw[0] ^= 1; hn[f] = base64.b64encode(bytes(raw)).decode()
    hk = dict(h); hk["key_id"] = "0" * 16
    hd = dict(h); hd["mode"] = "ECB"; hd["alg"] = "AES-256-ECB"
    ha = dict(h); ha["aad"] = "doc=2"
    return [
        (f"{mode.upper()}: зміна 1 біта шифртексту", lambda: decrypt(ks, flip(c, len(hb) + 5), PW)),
        (f"{mode.upper()}: зміна 1 біта тегу/MAC", lambda: decrypt(ks, flip(c, len(c) - 1), PW)),
        (f"{mode.upper()}: зміна заголовка (created)", lambda: decrypt(ks, flip(c, hb.index(b'"created"') + 14), PW)),
        (f"{mode.upper()}: підміна nonce/IV", lambda: decrypt(ks, pack_header(hn) + body, PW)),
        (f"{mode.upper()}: підміна AAD-контексту", lambda: decrypt(ks, pack_header(ha) + body, PW)),
        (f"{mode.upper()}: очікуваний інший AAD", lambda: decrypt(ks, c, PW, expect_aad="doc=2")),
        (f"{mode.upper()}: підміна key_id", lambda: decrypt(ks, pack_header(hk) + body, PW)),
        (f"{mode.upper()}: downgrade режиму на ECB", lambda: decrypt(ks, pack_header(hd) + body, PW)),
        (f"{mode.upper()}: обрізання контейнера", lambda: decrypt(ks, c[:-16], PW)),
        (f"{mode.upper()}: дописування даних", lambda: decrypt(ks, c + secrets.token_bytes(16), PW)),
    ]


def bitflip_cbc():
    c = encrypt(ks, MSG, "demo", PW, "cbc")
    return decrypt(ks, flip_xor(c, body_off(c) + 7, ord("1") ^ ord("9")), PW)


def flip_xor(blob, pos, x):
    b = bytearray(blob); b[pos] ^= x; return bytes(b)


def wrong_pw():
    return decrypt(ks, encrypt(ks, MSG, "demo", PW), "Guess-123")


def nonce_reuse():
    n = secrets.token_bytes(12)
    encrypt(ks, b"m1", "demo", PW, _force_iv=n)
    return encrypt(ks, b"m2", "demo", PW, _force_iv=n)


def foreign_key():
    return decrypt(ks, seal(MSG, secrets.token_bytes(32), ks.list("demo")[0].key_id), PW)


def weak_kdf():
    p = os.path.join(tmp, "weak.json")
    json.dump({"kdf": {"name": "PBKDF2-HMAC-SHA256", "iters": 20000}, "keys": []}, open(p, "w"))
    return KeyStore(p)


def garbage():
    return decrypt(ks, b"AKMS\x01" + secrets.token_bytes(64), PW)


def ecb_encrypt():
    return encrypt(ks, MSG, "demo", PW, mode="ecb")


SCEN = scen_gcm("gcm") + scen_gcm("cbc") + [
    ("CBC: bit-flipping amount=100→900", bitflip_cbc),
    ("Шифртекст іншим (чужим) ключем", foreign_key),
    ("Випадкове сміття замість контейнера", garbage),
    ("Невірний master-пароль", wrong_pw),
    ("Повторний nonce у GCM", nonce_reuse),
    ("Запит шифрування в режимі ECB", ecb_encrypt),
    ("Keystore зі слабким PBKDF2 (20 000 іт.)", weak_kdf),
]

results = []
for name, fn in SCEN:
    try:
        fn()
        res, cls, reason = "ПРИЙНЯТО (вразливість!)", "-", "-"
    except AKMSError as e:
        res, cls, reason = "ВІДМОВА", type(e).__name__, getattr(e, "reason", "-")
    results.append({"scenario": name, "result": res, "exception": cls, "reason": reason})

w = max(len(r["scenario"]) for r in results) + 2
print(f"{'Сценарій атаки':<{w}}{'Результат':<11}{'Виняток':<17}Внутр. причина (лише аудит)")
print("-" * (w + 56))
for r in results:
    print(f"{r['scenario']:<{w}}{r['result']:<11}{r['exception']:<17}{r['reason']}")
blocked = sum(r["result"] == "ВІДМОВА" for r in results)
print("-" * (w + 56))
print(f"Заблоковано: {blocked}/{len(results)}; повідомлення користувачу для ContainerError однакове: "
      f"«{ContainerError().args[0]}»")
os.makedirs(os.path.join(ROOT, "outputs"), exist_ok=True)
json.dump(results, open(os.path.join(ROOT, "outputs", "attack_results.json"), "w", encoding="utf-8"),
          ensure_ascii=False, indent=2)
sys.exit(0 if blocked == len(results) else 1)
