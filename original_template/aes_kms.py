import os, json, secrets, struct
from dataclasses import dataclass
from typing import Optional
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hmac as hmac_lib, padding

MAGIC = b'AKMS'
VERSION = 1

@dataclass
class KeyMeta:
    key_id: str
    label: str
    alg: str
    bits: int
    created: int
    state: str  # active|retiring|disabled
    uses: int

class KeyStore:
    def __init__(self, path='kms/keystore.json'):
        self.path = path
        self.db = {'kdf': {'name':'PBKDF2-HMAC-SHA256', 'iters': 200_000}, 'keys': []}
        if os.path.exists(path):
            self.db = json.load(open(path,'r',encoding='utf-8'))

    def save(self):
        json.dump(self.db, open(self.path,'w',encoding='utf-8'), ensure_ascii=False, indent=2)

    def _derive_kek(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=self.db['kdf']['iters'])
        return kdf.derive(password.encode())

    def new_key(self, label: str, password: str, bits: int = 256) -> KeyMeta:
        aes_key = secrets.token_bytes(bits//8)
        key_id = secrets.token_hex(8)
        salt = secrets.token_bytes(16)
        kek = self._derive_kek(password, salt)
        # Wrap key using AESGCM with random nonce
        nonce = secrets.token_bytes(12)
        enc = AESGCM(kek).encrypt(nonce, aes_key, None)
        meta = {'key_id': key_id, 'label': label, 'alg': 'AES', 'bits': bits, 'created': int(secrets.randbelow(2**31)), 'state': 'active', 'uses': 0,
                'wrap': {'salt': salt.hex(), 'nonce': nonce.hex(), 'blob': enc.hex()}}
        self.db['keys'].append(meta); self.save()
        return KeyMeta(**{k: meta[k] for k in ('key_id','label','alg','bits','created','state','uses')})

    def _unwrap(self, rec, password: str) -> bytes:
        salt = bytes.fromhex(rec['wrap']['salt'])
        nonce = bytes.fromhex(rec['wrap']['nonce'])
        blob = bytes.fromhex(rec['wrap']['blob'])
        kek = self._derive_kek(password, salt)
        return AESGCM(kek).decrypt(nonce, blob, None)

    def get_active_key(self, label: str, password: str):
        # Prefer active, fallback retiring
        for state in ('active','retiring'):
            for rec in self.db['keys']:
                if rec['label']==label and rec['state']==state:
                    return rec, self._unwrap(rec, password)
        raise KeyError('no key for label')

    def rotate(self, label: str, password: str):
        # Mark current active as retiring, add new active
        for rec in self.db['keys']:
            if rec['label']==label and rec['state']=='active':
                rec['state']='retiring'
                break
        self.save()
        return self.new_key(label, password)

# --- Containers ---

def pack_header(h: dict) -> bytes:
    blob = json.dumps(h, separators=(',',':')).encode('utf-8')
    return MAGIC + len(blob).to_bytes(2,'big') + blob

def unpack_header(fp):
    if fp.read(4)!=MAGIC: raise ValueError('bad magic')
    ln = int.from_bytes(fp.read(2),'big')
    return json.loads(fp.read(ln).decode('utf-8'))

# AES-GCM

def enc_gcm(in_path: str, out_path: str, key: bytes, key_id: str):
    data = open(in_path,'rb').read()
    nonce = secrets.token_bytes(12)
    h = {'v': VERSION, 'mode':'GCM', 'key_id': key_id, 'nonce': nonce.hex(), 'alg': f'AES-{len(key)*8}-GCM'}
    aad = pack_header(h)
    ct = AESGCM(key).encrypt(nonce, data, aad)
    with open(out_path,'wb') as f:
        f.write(aad); f.write(ct)


def dec_gcm(in_path: str, out_path: str, key: bytes):
    with open(in_path,'rb') as f:
        hdr = unpack_header(f)
        body = f.read()
    nonce = bytes.fromhex(hdr['nonce'])
    pt = AESGCM(key).decrypt(nonce, body, pack_header(hdr))
    open(out_path,'wb').write(pt)

# AES-CBC + HMAC (encrypt-then-MAC)

def enc_cbc_hmac(in_path: str, out_path: str, key: bytes, key_id: str):
    iv = secrets.token_bytes(16)
    enc_key = key
    mac_key = secrets.token_bytes(32)  # demo: зберігається в заголовку **зашифрованим** ключем (спрощено тут)
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    enc = cipher.encryptor(); padder = padding.PKCS7(128).padder()
    h = {'v': VERSION, 'mode':'CBC-HMAC', 'key_id': key_id, 'iv': iv.hex(), 'alg': f'AES-{len(enc_key)*8}-CBC', 'mac':'HMAC-SHA256', 'mk': mac_key.hex()}
    header = pack_header(h)
    with open(in_path,'rb') as fi:
        pt = fi.read()
    c = enc.update(padder.update(pt) + padder.finalize()) + enc.finalize()
    mac = hmac_lib.HMAC(mac_key, hashes.SHA256()); mac.update(header); mac.update(c)
    tag = mac.finalize()
    open(out_path,'wb').write(header + c + tag)


def dec_cbc_hmac(in_path: str, out_path: str, key: bytes):
    with open(in_path,'rb') as f:
        hdr = unpack_header(f)
        body = f.read()
    c, tag = body[:-32], body[-32:]
    mac_key = bytes.fromhex(hdr['mk'])
    mac = hmac_lib.HMAC(mac_key, hashes.SHA256()); mac.update(pack_header(hdr)); mac.update(c); mac.verify(tag)
    cipher = Cipher(algorithms.AES(key), modes.CBC(bytes.fromhex(hdr['iv'])))
    dec = cipher.decryptor(); unpad = padding.PKCS7(128).unpadder()
    pt = unpad.update(dec.update(c) + dec.finalize()) + unpad.finalize()
    open(out_path,'wb').write(pt)
