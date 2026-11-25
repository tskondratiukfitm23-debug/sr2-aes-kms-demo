"""Наочна демонстрація: чому ECB небезпечний. Зображення шифрується ECB / CBC / GCM
(лише для ілюстрації; ECB у модулі не підтримується). Результат: docs/screenshots/ecb_vs_gcm.png"""
import os
import secrets

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
W, H = 256, 160
img = np.full((H, W), 255, np.uint8)
fig = plt.figure(figsize=(W / 50, H / 50), dpi=50)
fig.text(0.5, 0.5, "AES", fontsize=95, weight="bold", ha="center", va="center")
fig.canvas.draw()
img = np.asarray(fig.canvas.buffer_rgba())[:, :, 0].copy()
plt.close(fig)
img = (img // 128 * 255).astype(np.uint8)          # чисто чорно-біле: великі однакові ділянки
raw = img.tobytes()
key = secrets.token_bytes(32)


def to_img(b):
    return np.frombuffer(b[: len(raw)], np.uint8).reshape(img.shape)


ecb = Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(raw)
cbc = Cipher(algorithms.AES(key), modes.CBC(secrets.token_bytes(16))).encryptor().update(raw)
gcm = AESGCM(key).encrypt(secrets.token_bytes(12), raw, None)

fig, ax = plt.subplots(1, 4, figsize=(14, 2.9))
for a, (t, im) in zip(ax, [("Відкритий текст", img), ("AES-ECB (структура видна!)", to_img(ecb)),
                           ("AES-CBC (шум)", to_img(cbc)), ("AES-GCM (шум + тег)", to_img(gcm))]):
    a.imshow(im, cmap="gray", vmin=0, vmax=255, interpolation="nearest"); a.set_title(t, fontsize=12); a.axis("off")
plt.tight_layout()
out = os.path.join(ROOT, "docs", "screenshots", "ecb_vs_gcm.png")
plt.savefig(out, dpi=110)
blocks = [raw[i:i + 16] for i in range(0, len(raw), 16)]
eb = [ecb[i:i + 16] for i in range(0, len(ecb), 16)]
print(f"Блоків: {len(blocks)}; унікальних блоків відкритого тексту: {len(set(blocks))}; "
      f"унікальних у ECB: {len(set(eb))}; у GCM: {len(set(gcm[i:i+16] for i in range(0, len(raw), 16)))}")
print("saved", out)
