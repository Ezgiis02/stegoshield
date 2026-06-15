# -*- coding: utf-8 -*-
"""
StegoShield — LSB steganaliz için güçlü özellik çıkarımı.
Hem eğitim (train_model.py) hem tahmin (app.py) bu fonksiyonları kullanır;
böylece özellikler birebir tutarlı olur.

Özellikler (5):
  1. chi2_prob    : Chi-square testine göre gömme olasılığı (0..1)
  2. rs_rate      : RS (Fridrich) tahmini gömme oranı (0..1)
  3. lsb_entropy  : LSB düzleminin entropisi (0..1)
  4. lsb_mean     : Ortalama LSB değeri (temiz≈doğal, stego≈0.5)
  5. blockchi_max : 64x64 bloklarda en yüksek chi-square gömme olasılığı (0..1)
"""
import numpy as np
from scipy.stats import chi2 as chi2dist

CROP = 256  # özellikler merkezi 256x256 kırpımdan hesaplanır (LSB korunur, hız sabit)

def _crop(img):
    h, w = img.shape[:2]
    y0 = max(0, (h - CROP) // 2); x0 = max(0, (w - CROP) // 2)
    return img[y0:y0+CROP, x0:x0+CROP]

def _chi_square_prob(img):
    probs = []
    for c in range(3):
        h = np.bincount(img[:, :, c].ravel(), minlength=256).astype(float)
        even, odd = h[0::2], h[1::2]
        exp = (even + odd) / 2
        mask = exp > 4
        if mask.sum() < 2:
            continue
        chi = np.sum((even[mask] - exp[mask]) ** 2 / exp[mask])
        df = int(mask.sum() - 1)
        probs.append(1 - chi2dist.cdf(chi, df))  # gömme olasılığı
    return float(np.mean(probs)) if probs else 0.0

def _rs_rate(img):
    R1 = S1 = Rm1 = Sm1 = total = 0
    for c in range(3):
        a = img[:, :-1, c].astype(int)
        b = img[:, 1:, c].astype(int)
        f0 = np.abs(b - a)
        a1 = a ^ 1
        f1 = np.abs(b - a1)
        R1 += np.sum(f1 > f0); S1 += np.sum(f1 < f0)
        am1 = np.where(a % 2 == 0, np.maximum(0, a - 1), np.minimum(255, a + 1))
        fm1 = np.abs(b - am1)
        Rm1 += np.sum(fm1 > f0); Sm1 += np.sum(fm1 < f0)
        total += a.size
    if total == 0:
        return 0.0
    r1, rm1 = R1 / total, Rm1 / total
    diff = r1 - rm1
    return float(min(1.0, max(0.0, diff / max(r1, 1e-4) * 2)))

def _lsb_stats(img):
    lsb = (img & 1).astype(float)
    mean = float(lsb.mean())
    p1 = mean; p0 = 1 - p1
    ent = 0.0
    if 0 < p1 < 1:
        ent = -(p0 * np.log2(p0) + p1 * np.log2(p1))
    return ent, mean

def _block_chi_max(img):
    h, w = img.shape[:2]
    bs = 64
    best = 0.0
    for by in range(0, h, bs):
        for bx in range(0, w, bs):
            blk = img[by:by+bs, bx:bx+bs]
            if blk.shape[0] < 16 or blk.shape[1] < 16:
                continue
            p = _chi_square_prob(blk)
            if p > best:
                best = p
    return best

def extract_lsb_features(img_bgr):
    """BGR uint8 görselden 5 özellikli vektör döndürür."""
    img = _crop(img_bgr)
    chi2_prob = _chi_square_prob(img)
    rs_rate = _rs_rate(img)
    lsb_entropy, lsb_mean = _lsb_stats(img)
    blockchi_max = _block_chi_max(img)
    return [chi2_prob, rs_rate, lsb_entropy, lsb_mean, blockchi_max]

FEATURE_NAMES = ['Chi2_Olasilik', 'RS_Orani', 'LSB_Entropi', 'LSB_Ortalama', 'Blok_Chi_Max']

def embed_lsb(img_bgr, rate, rng):
    """Görselin piksellerinin `rate` oranındaki LSB'lerine rastgele bit yazar (stego üretimi)."""
    out = img_bgr.copy()
    flat = out.reshape(-1, 3)
    n = flat.shape[0]
    k = int(n * rate)
    if k <= 0:
        return out
    idx = rng.choice(n, size=k, replace=False)
    bits = rng.integers(0, 2, size=(k, 3), dtype=np.uint8)
    flat[idx] = (flat[idx] & 0xFE) | bits
    return out
