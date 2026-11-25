import argparse, os, base64, time
from kms.aes_kms import KeyStore, enc_gcm, dec_gcm, enc_cbc_hmac, dec_cbc_hmac

DATA='data'; OUT='outputs'

os.makedirs(DATA, exist_ok=True); os.makedirs(OUT, exist_ok=True)


def key_cmd(args):
    ks = KeyStore()
    if args.action=='new':
        meta = ks.new_key(args.label, args.password)
        print('Created key:', meta)
    elif args.action=='rotate':
        meta = ks.rotate(args.label, args.password)
        print('Rotated; new key:', meta)
    elif args.action=='list':
        print(open('kms/keystore.json','r',encoding='utf-8').read())


def enc_cmd(args):
    ks = KeyStore(); rec, key = ks.get_active_key(args.label, args.password)
    if args.mode=='gcm': enc_gcm(args.infile, args.outfile, key, rec['key_id'])
    elif args.mode=='cbc': enc_cbc_hmac(args.infile, args.outfile, key, rec['key_id'])
    print('Encrypted:', args.outfile)


def dec_cmd(args):
    # Спроба GCM → CBC у демо-режимі (визначення з заголовка також можливе)
    try:
        dec_gcm(args.infile, args.outfile, KeyStore().get_active_key(args.label, args.password)[1])
        print('Decrypted (GCM)')
    except Exception:
        dec_cbc_hmac(args.infile, args.outfile, KeyStore().get_active_key(args.label, args.password)[1])
        print('Decrypted (CBC-HMAC)')


def tamper_cmd(args):
    b=bytearray(open(args.infile,'rb').read());
    if len(b)>20: b[20]^=0xFF
    open(args.infile,'wb').write(b); print('Tampered one byte in place')


if __name__=='__main__':
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest='cmd', required=True)

    pk = sp.add_parser('key'); sk = pk.add_subparsers(dest='action', required=True)
    sk.add_parser('list')
    pnew = sk.add_parser('new'); pnew.add_argument('--label', required=True); pnew.add_argument('--password', required=True)
    prot = sk.add_parser('rotate'); prot.add_argument('--label', required=True); prot.add_argument('--password', required=True)

    pe = sp.add_parser('enc'); pe.add_argument('--in', dest='infile', required=True); pe.add_argument('--out', dest='outfile', required=True); pe.add_argument('--mode', choices=['gcm','cbc'], required=True); pe.add_argument('--label', required=True); pe.add_argument('--password', required=True)
    pd = sp.add_parser('dec'); pd.add_argument('--in', dest='infile', required=True); pd.add_argument('--out', dest='outfile', required=True); pd.add_argument('--label', required=True); pd.add_argument('--password', required=True)

    pt = sp.add_parser('tamper'); pt.add_argument('--in', dest='infile', required=True)

    args = ap.parse_args()
    if args.cmd=='key': key_cmd(args)
    elif args.cmd=='enc': enc_cmd(args)
    elif args.cmd=='dec': dec_cmd(args)
    elif args.cmd=='tamper': tamper_cmd(args)
