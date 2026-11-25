"""Аудит вихідного шаблону (original_template/aes_kms.py): демонструє вади, виправлені в kms/aes_kms.py."""
import importlib.util
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("orig", os.path.join(ROOT, "original_template", "aes_kms.py"))
o = importlib.util.module_from_spec(spec); spec.loader.exec_module(o)
from cryptography.hazmat.primitives import hashes, hmac  # noqa: E402

t = tempfile.mkdtemp(); P = lambda n: os.path.join(t, n)  # noqa: E731
ks = o.KeyStore(P("ks.json")); ks.db["kdf"]["iters"] = 20000   # як у шаблонному keystore.json
ks.new_key("d", "pw"); rec, key = ks.get_active_key("d", "pw")
open(P("m"), "wb").write(b"0123456789ABCDEF" + b"amount=100;to=al")

# 1) MAC-ключ лежить у заголовку відкрито -> підробка: bit-flip + перерахунок HMAC
o.enc_cbc_hmac(P("m"), P("c"), key, rec["key_id"])
b = bytearray(open(P("c"), "rb").read()); hl = 6 + int.from_bytes(b[4:6], "big")
b[hl + 7] ^= ord("1") ^ ord("9")
hdr = json.loads(b[6:hl]); m = hmac.HMAC(bytes.fromhex(hdr["mk"]), hashes.SHA256())
m.update(bytes(b[:hl])); m.update(bytes(b[hl:-32])); b[-32:] = m.finalize()
open(P("c2"), "wb").write(b); o.dec_cbc_hmac(P("c2"), P("out"), key)
print("[ВАДА 1] CBC-HMAC шаблону: MAC-ключ у заголовку -> підроблено повідомлення:", open(P("out"), "rb").read()[16:])

# 2) Після ротації старі файли не розшифровуються (dec бере активний ключ, ігноруючи key_id)
o.enc_gcm(P("m"), P("g"), key, rec["key_id"]); ks.rotate("d", "pw")
try:
    o.dec_gcm(P("g"), P("out"), ks.get_active_key("d", "pw")[1]); print("[OK] dual-read")
except Exception as e:
    print("[ВАДА 2] Після rotate старий .gcm НЕ розшифровується (немає вибору ключа за key_id):", type(e).__name__)

# 3) Слабкі параметри / інше
print("[ВАДА 3] PBKDF2 у шаблонному keystore.json: 20 000 ітерацій (рекомендація OWASP: 600 000)")
print("[ВАДА 4] 'created' — випадкове число, а не час; немає журналу nonce, лімітів і стану disabled")
print("[ВАДА 5] CLI: при помилці GCM мовчки пробує CBC -> трасування Python із деталями (витік)")
print("[ВАДА 6] AES-GCM blob ключа не прив'язаний до метаданих (AAD=None), пароль у аргументах CLI")
print("Усі вади усунено в kms/aes_kms.py — див. tests/test_roundtrip.py та tools/attack_tests.py")
