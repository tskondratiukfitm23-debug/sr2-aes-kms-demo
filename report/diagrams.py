import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

OUT = "/home/ubuntu/sr2/docs/screenshots/"


def box(ax, x, y, w, h, text, fc="#e8f0fe", ec="#3367d6", fs=10, bold=False):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.08", fc=fc, ec=ec, lw=1.4))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs, weight="bold" if bold else "normal")


def arrow(ax, x1, y1, x2, y2, t="", dx=0, dy=0.12):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1), arrowprops=dict(arrowstyle="-|>", lw=1.3, color="#333"))
    if t:
        ax.text((x1 + x2) / 2 + dx, (y1 + y2) / 2 + dy, t, ha="center", fontsize=8.5, color="#333")


# 1. Архітектура
fig, ax = plt.subplots(figsize=(13, 6.6)); ax.set_xlim(0, 13); ax.set_ylim(0, 6.6); ax.axis("off")
box(ax, 0.2, 5.3, 3.0, 1.0, "Користувач\nmaster-пароль\n(getpass / AKMS_PASSWORD)", "#fff4e5", "#e8710a")
box(ax, 4.0, 5.3, 4.4, 1.0, "Застосунки: app/cli.py (CLI)\napp/vault.py («Захищений нотатник»)", "#e6f4ea", "#188038", bold=True)
box(ax, 9.2, 5.3, 3.6, 1.0, "Файли-контейнери AKMS v1\n*.gcm / *.cbc / *.akms", "#fce8e6", "#c5221f")
ax.add_patch(FancyBboxPatch((0.2, 0.2), 12.6, 4.6, boxstyle="round,pad=0.02", fc="#fafafa", ec="#999", ls="--"))
ax.text(0.45, 4.5, "kms/aes_kms.py", fontsize=11, weight="bold")
box(ax, 0.5, 2.9, 3.3, 1.3, "PBKDF2-HMAC-SHA256\n600 000 ітерацій\nсіль 16 Б (на ключ)\n→ KEK 256 біт")
box(ax, 4.3, 2.9, 3.7, 1.3, "KeyStore (KMS)\nnew / rotate / disable / migrate\nстани: active→retiring→disabled\nліміт uses, журнал nonce")
box(ax, 8.5, 2.9, 4.0, 1.3, "Шифрування (API encrypt/decrypt)\nAES-256-GCM (за замовчуванням)\nAES-256-CBC + HMAC-SHA256\n(HKDF: окремі ключі enc/MAC)")
box(ax, 0.5, 0.6, 3.3, 1.5, "kms/keystore.json (0600)\nметадані ключів +\nwrap: salt, nonce,\nblob = AES-GCM(KEK, ключ)", "#fff8e1", "#f9ab00")
box(ax, 4.3, 0.6, 3.7, 1.5, "Контейнер AKMS v1\nMAGIC|ver|len|JSON-заголовок|\nciphertext|tag/MAC\n(заголовок автентифікується)", "#fff8e1", "#f9ab00")
box(ax, 8.5, 0.6, 4.0, 1.5, "kms/audit.jsonl\nподії key_new/rotate/encrypt/\ndecrypt/decrypt_failed\n(без паролів, ключів, даних)", "#fff8e1", "#f9ab00")
arrow(ax, 3.2, 5.8, 4.0, 5.8, "пароль")
arrow(ax, 8.4, 5.8, 9.2, 5.8, "enc/dec")
arrow(ax, 6.2, 5.3, 6.2, 4.2, "виклики API", dx=0.7, dy=0)
arrow(ax, 3.8, 3.55, 4.3, 3.55, "KEK", dy=0.1)
arrow(ax, 8.0, 3.55, 8.5, 3.55, "ключ", dy=0.1)
arrow(ax, 2.15, 2.9, 2.15, 2.1); arrow(ax, 6.15, 2.9, 6.15, 2.1); arrow(ax, 10.5, 2.9, 10.5, 2.1)
plt.tight_layout(); plt.savefig(OUT + "arch.png", dpi=130); plt.close()

# 2. Формат контейнера
fig, ax = plt.subplots(figsize=(13, 3.4)); ax.set_xlim(0, 13); ax.set_ylim(0, 3.4); ax.axis("off")
parts = [("MAGIC\n\"AKMS\"\n4 Б", 1.2, "#e8eaed"), ("ver\n1 Б", 0.8, "#e8eaed"), ("len\n2 Б\n(BE)", 0.9, "#e8eaed"),
         ("JSON-заголовок\n{fmt, v, alg, mode, key_id,\nnonce|iv, aad, created[, mac]}\n≤ 4096 Б", 4.1, "#e8f0fe"),
         ("ciphertext\n(= довжина даних для GCM;\nPKCS#7 для CBC)", 3.4, "#fce8e6"), ("tag 16 Б (GCM)\nабо HMAC 32 Б", 2.2, "#e6f4ea")]
x = 0.2
for t, w, c in parts:
    box(ax, x, 1.35, w - 0.05, 1.5, t, c, "#555", 9); x += w
ax.annotate("", xy=(0.2, 1.1), xytext=(7.2, 1.1), arrowprops=dict(arrowstyle="<->"))
ax.text(3.7, 0.75, "AAD для GCM / вхід HMAC для CBC (весь заголовок автентифікується)", ha="center", fontsize=9)
ax.annotate("", xy=(7.2, 0.45), xytext=(12.8, 0.45), arrowprops=dict(arrowstyle="<->"))
ax.text(10.0, 0.1, "AESGCM.encrypt → ciphertext||tag;  CBC: HMAC(mac_key, заголовок||ciphertext)", ha="center", fontsize=9)
plt.tight_layout(); plt.savefig(OUT + "container.png", dpi=130); plt.close()

# 3. Життєвий цикл ключа
fig, ax = plt.subplots(figsize=(13, 2.8)); ax.set_xlim(0, 13); ax.set_ylim(0, 2.8); ax.axis("off")
box(ax, 0.2, 0.9, 2.4, 1.1, "key new\n(CSPRNG, AES-256)", "#e8eaed", "#555")
box(ax, 3.5, 0.9, 2.6, 1.1, "active\nencrypt + decrypt", "#e6f4ea", "#188038", bold=True)
box(ax, 7.0, 0.9, 2.6, 1.1, "retiring\nлише decrypt (dual-read)", "#fff8e1", "#f9ab00", bold=True)
box(ax, 10.4, 0.9, 2.4, 1.1, "disabled\nне використовується", "#fce8e6", "#c5221f", bold=True)
arrow(ax, 2.6, 1.45, 3.5, 1.45, "створення")
arrow(ax, 6.1, 1.45, 7.0, 1.45, "rotate", dy=0.15)
arrow(ax, 9.6, 1.45, 10.4, 1.45, "migrate+disable", dy=0.15)
ax.text(6.5, 0.35, "rotate — вручну, за лімітом uses (100 000) або строком (90 днів); новий key_id, version+1", ha="center", fontsize=9)
plt.tight_layout(); plt.savefig(OUT + "lifecycle.png", dpi=130); plt.close()
print("ok")
