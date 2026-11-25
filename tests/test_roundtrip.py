"""Тести AES-KMS: коректність (round-trip), негативні сценарії, ротація, політики, безпека журналу."""
import json
import os
import secrets

import pytest

from app import cli
from app.vault import Vault
from kms.aes_kms import (BadPassword, ContainerError, KeyPolicyError, KeyStateError, KeyStore,
                         NonceReuseError, WeakKdfError, AKMSError, PBKDF2_ITERS, decrypt, encrypt,
                         migrate_file, parse_container, seal, unseal, pack_header)

PW = "S3cure-Master-Pass!"


@pytest.fixture
def ks(tmp_path):
    k = KeyStore(path=tmp_path / "keystore.json")
    k.new_key("t", PW)
    return k


# ---------------------------------------------------------------- round-trip
@pytest.mark.parametrize("mode", ["gcm", "cbc"])
@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 1024, 1_000_003])
def test_roundtrip_sizes(ks, mode, size):
    data = secrets.token_bytes(size)
    hdr, pt = decrypt(ks, encrypt(ks, data, "t", PW, mode, aad="ctx"), PW, expect_aad="ctx")
    assert pt == data and hdr["mode"] == ("GCM" if mode == "gcm" else "CBC-HMAC")


def test_file_roundtrip_cli(tmp_path, ks):
    src = tmp_path / "sample.txt"; src.write_text("hello AES KMS demo\n", encoding="utf-8")
    k = str(tmp_path / "keystore.json")
    for mode in ("gcm", "cbc"):
        assert cli.main(["--keystore", k, "enc", "--in", str(src), "--out", str(tmp_path / f"s.{mode}"),
                         "--mode", mode, "--label", "t", "--password", PW]) == 0
        assert cli.main(["--keystore", k, "dec", "--in", str(tmp_path / f"s.{mode}"),
                         "--out", str(tmp_path / f"s.{mode}.dec"), "--password", PW]) == 0
        assert (tmp_path / f"s.{mode}.dec").read_bytes() == src.read_bytes()


def test_ciphertext_randomized(ks):
    """Семантична безпека: однаковий відкритий текст -> різні шифртексти (на відміну від ECB)."""
    a = encrypt(ks, b"A" * 64, "t", PW); b = encrypt(ks, b"A" * 64, "t", PW)
    assert a != b
    body = parse_container(a)[2][:-16]
    assert body[:16] != body[16:32]          # повтор блоків відкритого тексту не видно


# ---------------------------------------------------------------- tamper / атаки на цілісність
@pytest.mark.parametrize("mode", ["gcm", "cbc"])
@pytest.mark.parametrize("where", ["header", "nonce", "ct", "tag", "truncate", "append"])
def test_tamper_detected(ks, mode, where):
    blob = bytearray(encrypt(ks, b"amount=100;to=alice" * 4, "t", PW, mode))
    _, hb, body = parse_container(bytes(blob))
    if where == "header":
        blob[hb.index(b'"created"') + 14] ^= 1
    elif where == "nonce":
        h = json.loads(hb[7:]); f = "nonce" if mode == "gcm" else "iv"
        raw = bytearray(__import__("base64").b64decode(h[f])); raw[0] ^= 1
        h[f] = __import__("base64").b64encode(bytes(raw)).decode()
        blob = bytearray(pack_header(h) + body)
    elif where == "ct":
        blob[len(hb) + 3] ^= 1
    elif where == "tag":
        blob[-1] ^= 1
    elif where == "truncate":
        blob = blob[:-1] if mode == "gcm" else blob[:-16]
    else:
        blob += b"\x00" * 16
    with pytest.raises(ContainerError) as e:
        decrypt(ks, bytes(blob), PW)
    assert str(e.value) == "Дефект контейнера: перевірку автентичності не пройдено"   # уніфіковано


def test_cbc_bitflip_attack_blocked(ks):
    """Класична атака bit-flipping на CBC (зміна amount=100 -> 900) блокується HMAC."""
    pt = b"0123456789ABCDEF" + b"amount=100;to=al"
    blob = bytearray(encrypt(ks, pt, "t", PW, "cbc"))
    _, hb, _ = parse_container(bytes(blob))
    blob[len(hb) + 7] ^= ord("1") ^ ord("9")     # байт у C1 -> змінює P2[7]
    with pytest.raises(ContainerError) as e:
        decrypt(ks, bytes(blob), PW)
    assert e.value.reason == "cbc_mac"           # MAC перевірено ДО розшифрування (без padding oracle)


def test_header_downgrade_to_ecb_rejected(ks):
    blob = encrypt(ks, b"x" * 32, "t", PW)
    h, hb, body = parse_container(blob)
    h["mode"] = "ECB"; h["alg"] = "AES-256-ECB"
    with pytest.raises(ContainerError):
        decrypt(ks, pack_header(h) + body, PW)


@pytest.mark.parametrize("junk", [b"", b"AKMS", b"XXXX\x01\x00\x05hello", b"AKMS\x01\xff\xff{}",
                                  b"AKMS\x01\x00\x02{}", b"AKMS\x02\x00\x02{}" + b"0" * 32])
def test_invalid_container(ks, junk):
    with pytest.raises(ContainerError):
        decrypt(ks, junk, PW)


def test_aad_context_binding(tmp_path, ks):
    """Нотатку #1 підкладено замість #2 -> відмова (AAD прив'язує контейнер до контексту)."""
    v = Vault(ks, str(tmp_path / "vault"))
    v.add("a", "secret-1", PW); v.add("b", "secret-2", PW)
    assert v.show(1, PW)["text"] == "secret-1"
    os.replace(tmp_path / "vault" / "1.akms", tmp_path / "vault" / "2.akms")
    with pytest.raises(ContainerError) as e:
        v.show(2, PW)
    assert e.value.reason == "aad_mismatch"


def test_wrong_key_rejected(ks):
    blob = seal(b"data", secrets.token_bytes(32), "deadbeefdeadbeef")
    with pytest.raises(ContainerError):
        unseal(blob, secrets.token_bytes(32))


# ---------------------------------------------------------------- пароль / KDF
def test_wrong_password(ks):
    blob = encrypt(ks, b"data", "t", PW)
    with pytest.raises(BadPassword):
        decrypt(ks, blob, "wrong-password")
    with pytest.raises(BadPassword):
        encrypt(ks, b"data", "t", "wrong-password")
    with pytest.raises(BadPassword):
        ks.new_key("other", "wrong-password")      # лише той самий master-пароль


def test_weak_kdf_keystore_rejected(tmp_path):
    p = tmp_path / "weak.json"
    p.write_text(json.dumps({"kdf": {"name": "PBKDF2-HMAC-SHA256", "iters": 20000}, "keys": []}))
    with pytest.raises(WeakKdfError):
        KeyStore(path=p)


def test_keystore_has_no_plaintext_key(ks, tmp_path):
    raw = (tmp_path / "keystore.json").read_text()
    rec = json.loads(raw)["keys"][0]
    assert rec["wrap"]["iters"] == PBKDF2_ITERS >= 600_000
    assert len(__import__("base64").b64decode(rec["wrap"]["salt"])) == 16
    _, key = ks.active_key("t", PW)
    assert key.hex() not in raw and __import__("base64").b64encode(key).decode() not in raw
    assert PW not in raw
    if os.name == "posix":
        assert oct(os.stat(tmp_path / "keystore.json").st_mode)[-3:] == "600"


def test_wrapped_blob_bound_to_metadata(ks):
    ks.rotate("t", PW)
    a, b = ks.db["keys"]
    a["wrap"], b["wrap"] = b["wrap"], a["wrap"]          # підміна blob між записами
    with pytest.raises(BadPassword):
        ks.key_for_decrypt(a["key_id"], PW)


# ---------------------------------------------------------------- nonce
def test_nonce_reuse_rejected(ks):
    n = bytes(12)
    encrypt(ks, b"m1", "t", PW, _force_iv=n)
    with pytest.raises(NonceReuseError):
        encrypt(ks, b"m2", "t", PW, _force_iv=n)


def test_nonces_unique(ks):
    nonces = {parse_container(encrypt(ks, b"x", "t", PW))[0]["nonce"] for _ in range(300)}
    assert len(nonces) == 300


# ---------------------------------------------------------------- ротація / політики
def test_rotation_dual_read_and_migration(tmp_path, ks):
    old_id = ks.list("t")[0].key_id
    f = tmp_path / "doc.gcm"
    f.write_bytes(encrypt(ks, b"before rotation", "t", PW))
    new = ks.rotate("t", PW)
    states = {m.key_id: m.state for m in ks.list("t")}
    assert states == {old_id: "retiring", new.key_id: "active"} and new.version == 2
    # нове шифрування — новим ключем; старі дані — читаються старим (dual-read)
    assert parse_container(encrypt(ks, b"after", "t", PW))[0]["key_id"] == new.key_id
    assert decrypt(ks, f.read_bytes(), PW)[1] == b"before rotation"
    with pytest.raises(KeyStateError):
        ks.disable(new.key_id)                      # активний вимикати не можна
    assert migrate_file(ks, str(f), "t", PW) == (old_id, new.key_id)
    ks.disable(old_id)
    assert decrypt(ks, f.read_bytes(), PW)[1] == b"before rotation"
    old_blob = seal(b"z", ks.key_for_decrypt(new.key_id, PW)[1], old_id)
    with pytest.raises(KeyStateError):
        decrypt(ks, old_blob, PW)                   # disabled — не розшифровує


def test_usage_limit_policy(tmp_path):
    k = KeyStore(path=tmp_path / "ks.json")
    k.new_key("lim", PW, max_uses=3)
    for _ in range(3):
        encrypt(k, b"x", "lim", PW)
    with pytest.raises(KeyPolicyError):
        encrypt(k, b"x", "lim", PW)
    k.rotate("lim", PW)
    encrypt(k, b"x", "lim", PW)


def test_new_key_requires_rotate(ks):
    with pytest.raises(KeyStateError):
        ks.new_key("t", PW)


def test_ecb_mode_not_supported(ks):
    with pytest.raises(AKMSError):
        encrypt(ks, b"x", "t", PW, mode="ecb")


# ---------------------------------------------------------------- журнал без секретів
def test_audit_log_has_no_secrets(tmp_path, ks):
    data = b"TOP-SECRET-PAYLOAD"
    blob = encrypt(ks, data, "t", PW)
    decrypt(ks, blob, PW)
    with pytest.raises(BadPassword):
        decrypt(ks, blob, "bad-pass-123")
    log = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    _, key = ks.active_key("t", PW)
    for s in (PW, "bad-pass-123", data.decode(), key.hex(), __import__("base64").b64encode(key).decode()):
        assert s not in log
    assert '"event": "encrypt"' in log and '"event": "decrypt"' in log
