from kms.aes_kms import KeyStore, enc_gcm, dec_gcm, enc_cbc_hmac, dec_cbc_hmac
import os, secrets

def test_gcm_roundtrip(tmp_path):
    ks = KeyStore(path=tmp_path/'keystore.json')
    meta = ks.new_key('t', 'pass')
    data = secrets.token_bytes(1024)
    (tmp_path/'in').write_bytes(data)
    enc = tmp_path/'enc.gcm'; dec = tmp_path/'dec'
    rec, key = ks.get_active_key('t','pass')
    enc_gcm(str(tmp_path/'in'), str(enc), key, rec['key_id'])
    dec_gcm(str(enc), str(dec), key)
    assert (tmp_path/'dec').read_bytes()==data


def test_cbc_hmac_roundtrip(tmp_path):
    ks = KeyStore(path=tmp_path/'keystore.json')
    ks.new_key('t','pass')
    data = secrets.token_bytes(2048)
    (tmp_path/'in').write_bytes(data)
    rec, key = ks.get_active_key('t','pass')
    enc_cbc_hmac(str(tmp_path/'in'), str(tmp_path/'enc.cbc'), key, rec['key_id'])
    dec_cbc_hmac(str(tmp_path/'enc.cbc'), str(tmp_path/'dec'), key)
    assert (tmp_path/'dec').read_bytes()==data
