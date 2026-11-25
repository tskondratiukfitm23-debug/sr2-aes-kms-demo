"""AES-KMS — безпечний модуль шифрування AES та управління ключами (СР №2).

* Режим за замовчуванням — AES-256-GCM (AEAD, NIST SP 800-38D).
* Режим сумісності — AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC, NIST SP 800-38A + FIPS 198-1).
* ECB/CFB/OFB без автентифікації свідомо НЕ підтримуються.
* Ключі: master-пароль -> PBKDF2-HMAC-SHA256 (600 000 ітерацій, сіль 16 Б) -> KEK;
  робочі ключі AES-256 (CSPRNG) зберігаються лише у вигляді зашифрованого KEK blob (AES-GCM).
* Ротація: новий key_id (active), попередній -> retiring (лише розшифрування), після міграції -> disabled.
* Контейнер: MAGIC | ver | len | JSON-заголовок | ciphertext | tag(GCM)/MAC(CBC-HMAC).
  Увесь заголовок автентифікується (AAD для GCM / вхід HMAC для CBC).
* Помилки розшифрування уніфіковані: ContainerError «дефект контейнера» без деталей.
* Секрети (паролі, ключі, відкритий текст) ніколи не журналюються.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives import hmac as chmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"AKMS"
FORMAT_VERSION = 1
KDF_NAME = "PBKDF2-HMAC-SHA256"
PBKDF2_ITERS = 600_000          # OWASP Password Storage Cheat Sheet (PBKDF2-HMAC-SHA256)
PBKDF2_MIN_ITERS = 600_000      # нижче — WeakKdfError
SALT_BYTES = 16                 # NIST SP 800-132: >= 128 біт
KEY_BITS = 256
GCM_NONCE = 12                  # 96 біт — рекомендовано SP 800-38D
GCM_TAG = 16                    # 128-бітний тег
CBC_IV = 16
HMAC_LEN = 32
MAX_HEADER = 4096
DEFAULT_MAX_USES = 100_000      # політика: ліміт операцій шифрування на ключ (< 2^32, SP 800-38D §8.3)
DEFAULT_MAX_AGE_DAYS = 90       # політика: плановий строк життя ключа
STATES = ("active", "retiring", "disabled")
MODES = {"GCM": "AES-256-GCM", "CBC-HMAC": "AES-256-CBC+HMAC-SHA256"}
HEADER_FIELDS = {
    "GCM": {"fmt", "v", "alg", "mode", "key_id", "nonce", "aad", "created"},
    "CBC-HMAC": {"fmt", "v", "alg", "mode", "key_id", "iv", "aad", "created", "mac"},
}
UNIFIED_MSG = "Дефект контейнера: перевірку автентичності не пройдено"


# ------------------------------------------------------------------ винятки
class AKMSError(Exception):
    code = 1


class ContainerError(AKMSError):
    """Уніфікована помилка розшифрування (без витоку причини користувачу)."""
    code = 2

    def __init__(self, reason: str = "unspecified"):
        super().__init__(UNIFIED_MSG)
        self.reason = reason      # лише для внутрішнього аудиту/тестів, не секрет


class BadPassword(AKMSError):
    code = 3

    def __init__(self):
        super().__init__("Невірний master-пароль (KEK не розгортає ключ)")


class KeyPolicyError(AKMSError):
    code = 4


class KeyStateError(AKMSError):
    code = 4


class KeyNotFound(AKMSError):
    code = 4


class WeakKdfError(AKMSError):
    code = 4


class NonceReuseError(AKMSError):
    code = 5


# ------------------------------------------------------------------ утиліти
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class KeyMeta:
    key_id: str
    label: str
    version: int
    alg: str
    created: str
    state: str
    uses: int
    max_uses: int

    def __str__(self) -> str:
        return (f"key_id={self.key_id} label={self.label} v{self.version} {self.alg} "
                f"state={self.state} uses={self.uses}/{self.max_uses} created={self.created}")


def _meta(rec: dict) -> KeyMeta:
    return KeyMeta(rec["key_id"], rec["label"], rec["version"], rec["alg"], rec["created"],
                   rec["state"], rec["uses"], rec["max_uses"])


# ------------------------------------------------------------------ сховище ключів (KMS)
class KeyStore:
    """Сховище ключів: метадані відкрито, матеріал ключів — лише зашифрований KEK."""

    def __init__(self, path: str = "kms/keystore.json", audit_path: str | None = None):
        self.path = str(path)
        self.audit_path = audit_path if audit_path is not None else os.path.join(
            os.path.dirname(self.path) or ".", "audit.jsonl")
        self._kek_cache: dict[bytes, bytes] = {}
        if os.path.exists(self.path):
            with open(self.path, encoding="utf-8") as f:
                self.db = json.load(f)
        else:
            self.db = {"format": "AKMS-keystore", "v": 1,
                       "kdf": {"name": KDF_NAME, "iters": PBKDF2_ITERS, "salt_bytes": SALT_BYTES},
                       "policy": {"max_uses": DEFAULT_MAX_USES, "max_age_days": DEFAULT_MAX_AGE_DAYS},
                       "keys": []}
        kdf = self.db.get("kdf", {})
        if kdf.get("name") != KDF_NAME or int(kdf.get("iters", 0)) < PBKDF2_MIN_ITERS:
            raise WeakKdfError(f"Слабкі параметри KDF у {self.path}: {kdf} "
                               f"(потрібно {KDF_NAME}, >= {PBKDF2_MIN_ITERS} ітерацій)")
        self.db.setdefault("policy", {"max_uses": DEFAULT_MAX_USES, "max_age_days": DEFAULT_MAX_AGE_DAYS})

    # --- службове
    def save(self) -> None:
        d = os.path.dirname(os.path.abspath(self.path))
        os.makedirs(d, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=d, prefix=".ks_")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(self.db, f, ensure_ascii=False, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)          # атомарний запис

    def audit(self, event: str, **fields) -> None:
        """Журнал аудиту (JSONL). Лише несекретні поля."""
        if not self.audit_path:
            return
        forbidden = {"password", "key", "kek", "plaintext", "data"}
        rec = {"ts": now_iso(), "event": event}
        rec.update({k: v for k, v in fields.items() if k not in forbidden})
        with open(self.audit_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def _derive_kek(self, password: str, salt: bytes, iters: int) -> bytes:
        if not password:
            raise BadPassword()
        ck = salt + iters.to_bytes(4, "big") + password.encode("utf-8")
        if ck not in self._kek_cache:
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iters)
            self._kek_cache = {ck: kdf.derive(password.encode("utf-8"))}   # кеш лише 1 KEK
        return self._kek_cache[ck]

    @staticmethod
    def _wrap_aad(rec: dict) -> bytes:
        # прив'язує blob до метаданих: підміна blob між записами -> InvalidTag
        return f"AKMS-KEY|{rec['key_id']}|{rec['label']}|{rec['version']}|{rec['alg']}".encode()

    def _unwrap(self, rec: dict, password: str) -> bytes:
        w = rec["wrap"]
        kek = self._derive_kek(password, b64d(w["salt"]), int(w["iters"]))
        try:
            return AESGCM(kek).decrypt(b64d(w["nonce"]), b64d(w["blob"]), self._wrap_aad(rec))
        except InvalidTag:
            self.audit("unwrap_failed", key_id=rec["key_id"], label=rec["label"])
            raise BadPassword() from None

    def _records(self, label: str | None = None) -> list[dict]:
        return [r for r in self.db["keys"] if label is None or r["label"] == label]

    def _check_master(self, password: str) -> None:
        """Нові ключі дозволено створювати лише тим самим master-паролем."""
        recs = [r for r in self.db["keys"] if r["state"] != "disabled"]
        if recs:
            self._unwrap(recs[0], password)

    # --- генерація / ротація / виведення з обігу
    def new_key(self, label: str, password: str, max_uses: int | None = None) -> KeyMeta:
        self._check_master(password)
        if any(r["state"] == "active" for r in self._records(label)):
            raise KeyStateError(f"Для мітки '{label}' вже є активний ключ — використовуйте rotate")
        return self._create(label, password, max_uses)

    def _create(self, label: str, password: str, max_uses: int | None) -> KeyMeta:
        aes_key = secrets.token_bytes(KEY_BITS // 8)          # CSPRNG (os.urandom)
        salt = secrets.token_bytes(SALT_BYTES)
        iters = int(self.db["kdf"]["iters"])
        existing = {r["key_id"] for r in self.db["keys"]}
        key_id = secrets.token_hex(8)
        while key_id in existing:
            key_id = secrets.token_hex(8)
        rec = {"key_id": key_id, "label": label,
               "version": 1 + max([r["version"] for r in self._records(label)] or [0]),
               "alg": f"AES-{KEY_BITS}", "created": now_iso(), "state": "active", "uses": 0,
               "max_uses": int(max_uses or self.db["policy"]["max_uses"]),
               "retired": None, "nonces": []}
        kek = self._derive_kek(password, salt, iters)
        wnonce = secrets.token_bytes(GCM_NONCE)
        blob = AESGCM(kek).encrypt(wnonce, aes_key, self._wrap_aad(rec))
        rec["wrap"] = {"kdf": KDF_NAME, "iters": iters, "salt": b64e(salt),
                       "alg": "AES-256-GCM", "nonce": b64e(wnonce), "blob": b64e(blob)}
        self.db["keys"].append(rec)
        self.save()
        self.audit("key_new", key_id=key_id, label=label, version=rec["version"])
        return _meta(rec)

    def rotate(self, label: str, password: str, max_uses: int | None = None) -> KeyMeta:
        self._check_master(password)
        old = [r for r in self._records(label) if r["state"] == "active"]
        for r in old:
            self._unwrap(r, password)                    # перевірка пароля ДО змін
        for r in old:
            r["state"] = "retiring"
            r["retired"] = now_iso()
        meta = self._create(label, password, max_uses)
        self.audit("key_rotate", label=label, new_key_id=meta.key_id,
                   retiring=[r["key_id"] for r in old])
        return meta

    def disable(self, key_id: str) -> KeyMeta:
        rec = self._by_id(key_id)
        if rec["state"] == "active":
            raise KeyStateError("Активний ключ не можна вимкнути — спочатку rotate")
        rec["state"] = "disabled"
        self.save()
        self.audit("key_disable", key_id=key_id, label=rec["label"])
        return _meta(rec)

    def list(self, label: str | None = None) -> list[KeyMeta]:
        return [_meta(r) for r in self._records(label)]

    def _by_id(self, key_id: str) -> dict:
        for r in self.db["keys"]:
            if r["key_id"] == key_id:
                return r
        raise KeyNotFound(f"Ключ {key_id} не знайдено")

    # --- отримання ключів
    def active_key(self, label: str, password: str) -> tuple[dict, bytes]:
        """Ключ для ШИФРУВАННЯ: лише active + перевірка політики."""
        recs = [r for r in self._records(label) if r["state"] == "active"]
        if not recs:
            raise KeyNotFound(f"Немає активного ключа для мітки '{label}'")
        rec = recs[0]
        if rec["uses"] >= rec["max_uses"]:
            raise KeyPolicyError(f"Ключ {rec['key_id']} вичерпав ліміт {rec['max_uses']} операцій — виконайте rotate")
        age = datetime.now(timezone.utc) - datetime.fromisoformat(rec["created"])
        if age > timedelta(days=int(self.db["policy"]["max_age_days"])):
            raise KeyPolicyError(f"Ключ {rec['key_id']} старший за {self.db['policy']['max_age_days']} днів — виконайте rotate")
        return rec, self._unwrap(rec, password)

    def key_for_decrypt(self, key_id: str, password: str) -> tuple[dict, bytes]:
        """Ключ для РОЗШИФРУВАННЯ (dual-read): active або retiring, але не disabled."""
        rec = self._by_id(key_id)
        if rec["state"] == "disabled":
            raise KeyStateError(f"Ключ {key_id} вимкнено (disabled)")
        return rec, self._unwrap(rec, password)

    def reserve_nonce(self, rec: dict, nonce: bytes) -> None:
        """Журнал nonce/IV: повторне використання для того самого ключа -> відмова."""
        n = b64e(nonce)
        if n in rec["nonces"]:
            self.audit("nonce_reuse_blocked", key_id=rec["key_id"])
            raise NonceReuseError(f"Повторний nonce/IV для ключа {rec['key_id']} — операцію заборонено")
        rec["nonces"].append(n)
        rec["uses"] += 1
        self.save()


# ------------------------------------------------------------------ контейнер
def pack_header(h: dict) -> bytes:
    blob = json.dumps(h, separators=(",", ":"), sort_keys=True, ensure_ascii=False).encode("utf-8")
    if len(blob) > MAX_HEADER:
        raise AKMSError("Завеликий заголовок")
    return MAGIC + bytes([FORMAT_VERSION]) + len(blob).to_bytes(2, "big") + blob


def parse_container(blob: bytes) -> tuple[dict, bytes, bytes]:
    """Сувора валідація структури. Повертає (header, header_bytes, body). Будь-яка вада -> ContainerError."""
    if len(blob) < 7 or blob[:4] != MAGIC:
        raise ContainerError("bad_magic")
    if blob[4] != FORMAT_VERSION:
        raise ContainerError("bad_version")
    hlen = int.from_bytes(blob[5:7], "big")
    if hlen == 0 or hlen > MAX_HEADER or len(blob) < 7 + hlen:
        raise ContainerError("bad_header_len")
    hbytes = blob[: 7 + hlen]
    try:
        h = json.loads(blob[7: 7 + hlen].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ContainerError("bad_header_json") from None
    if not isinstance(h, dict) or h.get("mode") not in HEADER_FIELDS:
        raise ContainerError("bad_mode")
    if set(h) != HEADER_FIELDS[h["mode"]] or h.get("fmt") != "AKMS" or h.get("v") != FORMAT_VERSION:
        raise ContainerError("bad_header_fields")
    if h["alg"] != MODES[h["mode"]] or not isinstance(h["aad"], str):
        raise ContainerError("bad_alg")
    try:
        iv = b64d(h["nonce"] if h["mode"] == "GCM" else h["iv"])
    except Exception:
        raise ContainerError("bad_nonce") from None
    if len(iv) != (GCM_NONCE if h["mode"] == "GCM" else CBC_IV):
        raise ContainerError("bad_nonce_len")
    body = blob[7 + hlen:]
    if h["mode"] == "GCM" and len(body) < GCM_TAG:
        raise ContainerError("short_body")
    if h["mode"] == "CBC-HMAC" and (len(body) < 16 + HMAC_LEN or (len(body) - HMAC_LEN) % 16):
        raise ContainerError("short_body")
    return h, hbytes, body


def _cbc_keys(data_key: bytes) -> tuple[bytes, bytes]:
    """Розділення ключів для CBC+HMAC через HKDF-SHA256 (окремі ключі шифрування та MAC)."""
    okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=b"AKMS/v1/CBC-HMAC").derive(data_key)
    return okm[:32], okm[32:]


def seal(data: bytes, key: bytes, key_id: str, mode: str = "GCM", aad: str = "",
         iv: bytes | None = None) -> bytes:
    """Низькорівневе шифрування в контейнер (без звернення до KeyStore)."""
    mode = mode.upper()
    if mode in ("GCM",):
        nonce = iv if iv is not None else secrets.token_bytes(GCM_NONCE)
        h = {"fmt": "AKMS", "v": FORMAT_VERSION, "alg": MODES["GCM"], "mode": "GCM",
             "key_id": key_id, "nonce": b64e(nonce), "aad": aad, "created": now_iso()}
        hb = pack_header(h)
        return hb + AESGCM(key).encrypt(nonce, data, hb)           # ct || tag(16)
    if mode in ("CBC", "CBC-HMAC"):
        ivb = iv if iv is not None else secrets.token_bytes(CBC_IV)
        enc_key, mac_key = _cbc_keys(key)
        h = {"fmt": "AKMS", "v": FORMAT_VERSION, "alg": MODES["CBC-HMAC"], "mode": "CBC-HMAC",
             "key_id": key_id, "iv": b64e(ivb), "aad": aad, "created": now_iso(), "mac": "HMAC-SHA256"}
        hb = pack_header(h)
        padder = padding.PKCS7(128).padder()
        enc = Cipher(algorithms.AES(enc_key), modes.CBC(ivb)).encryptor()
        ct = enc.update(padder.update(data) + padder.finalize()) + enc.finalize()
        m = chmac.HMAC(mac_key, hashes.SHA256())
        m.update(hb + ct)                                          # encrypt-then-MAC (заголовок+шифртекст)
        return hb + ct + m.finalize()
    raise AKMSError(f"Режим {mode} не підтримується (дозволено: gcm, cbc). ECB заборонено.")


def unseal(blob: bytes, key: bytes, expect_aad: str | None = None) -> tuple[dict, bytes]:
    """Низькорівневе розшифрування: тег/MAC перевіряються ДО будь-якого розпакування."""
    h, hb, body = parse_container(blob)
    if h["mode"] == "GCM":
        try:
            pt = AESGCM(key).decrypt(b64d(h["nonce"]), body, hb)
        except InvalidTag:
            raise ContainerError("gcm_tag") from None
    else:
        enc_key, mac_key = _cbc_keys(key)
        ct, tag = body[:-HMAC_LEN], body[-HMAC_LEN:]
        m = chmac.HMAC(mac_key, hashes.SHA256())
        m.update(hb + ct)
        try:
            m.verify(tag)                                          # порівняння за сталий час
        except InvalidSignature:
            raise ContainerError("cbc_mac") from None
        try:
            dec = Cipher(algorithms.AES(enc_key), modes.CBC(b64d(h["iv"]))).decryptor()
            unp = padding.PKCS7(128).unpadder()
            pt = unp.update(dec.update(ct) + dec.finalize()) + unp.finalize()
        except ValueError:
            raise ContainerError("cbc_padding") from None
    if expect_aad is not None and h["aad"] != expect_aad:
        raise ContainerError("aad_mismatch")
    return h, pt


# ------------------------------------------------------------------ високорівневе API (для застосунків)
def encrypt(ks: KeyStore, data: bytes, label: str, password: str, mode: str = "gcm",
            aad: str = "", _force_iv: bytes | None = None) -> bytes:
    """Шифрує активним ключем мітки. _force_iv — лише для тестування захисту від повтору nonce."""
    rec, key = ks.active_key(label, password)
    m = "GCM" if mode.lower() == "gcm" else "CBC-HMAC" if mode.lower() in ("cbc", "cbc-hmac") else mode
    if m not in MODES:
        raise AKMSError(f"Режим {mode} не підтримується (дозволено: gcm, cbc). ECB заборонено.")
    iv = _force_iv if _force_iv is not None else secrets.token_bytes(GCM_NONCE if m == "GCM" else CBC_IV)
    ks.reserve_nonce(rec, iv)
    out = seal(data, key, rec["key_id"], m, aad, iv)
    ks.audit("encrypt", key_id=rec["key_id"], label=rec["label"], mode=m, size=len(data))
    return out


def decrypt(ks: KeyStore, blob: bytes, password: str, expect_aad: str | None = None) -> tuple[dict, bytes]:
    """Розшифровує ключем із key_id заголовка (dual-read: active/retiring)."""
    try:
        h, _, _ = parse_container(blob)
        try:
            rec, key = ks.key_for_decrypt(h["key_id"], password)
        except KeyNotFound:
            raise ContainerError("unknown_key_id") from None
        hdr, pt = unseal(blob, key, expect_aad)
    except ContainerError as e:
        ks.audit("decrypt_failed", reason=e.reason)
        raise
    ks.audit("decrypt", key_id=rec["key_id"], label=rec["label"], mode=hdr["mode"], state=rec["state"])
    return hdr, pt


def encrypt_file(ks: KeyStore, src: str, dst: str, label: str, password: str,
                 mode: str = "gcm", aad: str | None = None) -> dict:
    with open(src, "rb") as f:
        data = f.read()
    blob = encrypt(ks, data, label, password, mode, aad if aad is not None else f"file={os.path.basename(src)}")
    with open(dst, "wb") as f:
        f.write(blob)
    return parse_container(blob)[0]


def decrypt_file(ks: KeyStore, src: str, dst: str, password: str, expect_aad: str | None = None) -> dict:
    with open(src, "rb") as f:
        blob = f.read()
    hdr, pt = decrypt(ks, blob, password, expect_aad)
    with open(dst, "wb") as f:              # пишемо лише ПІСЛЯ успішної перевірки тегу/MAC
        f.write(pt)
    return hdr


def migrate_file(ks: KeyStore, path: str, label: str, password: str) -> tuple[str, str]:
    """Перешифрування контейнера активним ключем (завершення ротації). Повертає (old_id, new_id)."""
    with open(path, "rb") as f:
        blob = f.read()
    hdr, pt = decrypt(ks, blob, password)
    new = encrypt(ks, pt, label, password, "gcm" if hdr["mode"] == "GCM" else "cbc", hdr["aad"])
    with open(path, "wb") as f:
        f.write(new)
    return hdr["key_id"], parse_container(new)[0]["key_id"]
