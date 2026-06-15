# -*- coding: utf-8 -*-
"""
StegoShield ML — gerçek RGB görsellerle steganaliz modeli eğitimi.
Ekran görüntüsü klasöründen kapak görselleri alır; her biri için temiz (0) ve
stego (1) örnekler üretir, güçlü LSB özelliklerini çıkarır, Random Forest eğitir
ve modeli backend için kaydeder.
"""
import os, glob, sys
import numpy as np
import cv2
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupShuffleSplit, GroupKFold
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report

from features import extract_lsb_features, embed_lsb, FEATURE_NAMES

COVER_DIR = r'C:\Users\ezgis\Pictures\Screenshots'
MAX_IMAGES = 180          # hız için örneklenecek kapak görseli sayısı
MIN_SIDE = 64             # çok küçük görselleri atla
EMBED_RATES = [0.25, 0.5, 0.75, 1.0]  # çeşitli gömme oranları

def imread_unicode(path):
    """cv2.imread Windows'ta Türkçe/Unicode yolları okuyamaz; bayt okuyup decode ederiz."""
    try:
        data = np.fromfile(path, dtype=np.uint8)
        return cv2.imdecode(data, cv2.IMREAD_COLOR)
    except Exception:
        return None

def load_covers():
    paths = sorted(glob.glob(os.path.join(COVER_DIR, '*.png')) +
                   glob.glob(os.path.join(COVER_DIR, '*.jpg')))
    rng = np.random.default_rng(7)
    rng.shuffle(paths)
    covers = []
    for p in paths:
        img = imread_unicode(p)
        if img is None:
            continue
        h, w = img.shape[:2]
        if min(h, w) < MIN_SIDE:
            continue
        covers.append(img)
        if len(covers) >= MAX_IMAGES:
            break
    return covers

def synthetic_covers(n=45):
    """Düz/gradyan/yumuşak sentetik temiz görseller — modelin bu tür görselleri
    yanlışlıkla 'stego' saymasını önlemek için negatif örnek çeşitliliği."""
    rng = np.random.default_rng(99)
    out = []
    for _ in range(n):
        s = int(rng.integers(96, 256))
        kind = rng.integers(0, 4)
        if kind == 0:  # düz renk + hafif doğal gürültü
            base = rng.integers(0, 256, 3)
            img = np.ones((s, s, 3), np.float64) * base
            img += rng.normal(0, 2, (s, s, 3))
        elif kind == 1:  # yatay/dikey gradyan
            g = np.linspace(rng.integers(0, 128), rng.integers(128, 256), s)
            img = np.stack([np.tile(g, (s, 1))] * 3, axis=2)
            if rng.random() < 0.5:
                img = img.transpose(1, 0, 2)
        elif kind == 2:  # yumuşak sinüs dokusu
            x = np.arange(s)
            gx = 128 + 80 * np.sin(x / rng.uniform(8, 30))
            img = np.stack([np.tile(gx, (s, 1))] * 3, axis=2)
        else:  # bloklu düz renkler (UI benzeri)
            img = np.zeros((s, s, 3), np.float64)
            for _b in range(rng.integers(3, 8)):
                y0, x0 = rng.integers(0, s, 2); h, w = rng.integers(10, s, 2)
                img[y0:y0+h, x0:x0+w] = rng.integers(0, 256, 3)
        out.append(np.clip(img, 0, 255).astype(np.uint8))
    return out

def main():
    print('Kapak gorselleri yukleniyor...')
    covers = load_covers()
    print(f'  {len(covers)} gerçek görsel kullanilacak.')

    rng = np.random.default_rng(42)
    X, y, groups = [], [], []
    for i, img in enumerate(covers):
        # Temiz örnek (etiket 0) — aynı kapaktan iki örnek aynı gruba (i) ait
        X.append(extract_lsb_features(img)); y.append(0); groups.append(i)
        # Stego örnek (etiket 1, rastgele gömme oranı)
        stego = embed_lsb(img, float(rng.choice(EMBED_RATES)), rng)
        X.append(extract_lsb_features(stego)); y.append(1); groups.append(i)
        if (i + 1) % 30 == 0:
            print(f'  {i+1}/{len(covers)} islendi...')

    X, y, groups = np.array(X), np.array(y), np.array(groups)
    print(f'Toplam ornek: {len(y)}  (temiz={np.sum(y==0)}, stego={np.sum(y==1)})')

    # Regülarize edilmiş RF (overfit'i azaltmak için sığ ağaçlar + yaprak alt sınırı)
    def make_clf():
        return RandomForestClassifier(n_estimators=300, max_depth=8, min_samples_leaf=4,
                                      min_samples_split=10, max_features='sqrt', random_state=42)

    # GroupKFold ile dürüst genelleme tahmini (aynı kapak hiç bölünmez → leakage yok)
    gkf = GroupKFold(n_splits=5)
    cv_accs = []
    for tr, te in gkf.split(X, y, groups):
        c = make_clf().fit(X[tr], y[tr])
        cv_accs.append(accuracy_score(y[te], c.predict(X[te])))
    cv_acc = float(np.mean(cv_accs))
    print(f'\nGroupKFold 5-kat CV dogruluk: %{cv_acc*100:.2f} (+/- %{np.std(cv_accs)*100:.2f})')

    # Gruplu tek bölme — train/test farkı (overfit göstergesi) + rapor metrikleri
    gss = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=42)
    tr_i, te_i = next(gss.split(X, y, groups))
    clf = make_clf().fit(X[tr_i], y[tr_i])
    tr_acc = accuracy_score(y[tr_i], clf.predict(X[tr_i]))
    yp = clf.predict(X[te_i]); te_acc = accuracy_score(y[te_i], yp)
    print(f'Train dogruluk: %{tr_acc*100:.2f}  |  Test dogruluk: %{te_acc*100:.2f}  (fark: %{(tr_acc-te_acc)*100:.2f})')

    cm = confusion_matrix(y[te_i], yp)
    print('Karisiklik matrisi:'); print(f'  Gercek Temiz: {cm[0]}'); print(f'  Gercek Stego: {cm[1]}')
    print(classification_report(y[te_i], yp, target_names=['Temiz', 'Stego'], digits=3))
    print('Ozellik onemi:')
    for n, imp in sorted(zip(FEATURE_NAMES, clf.feature_importances_), key=lambda kv: -kv[1]):
        print(f'  {n:16s} %{imp*100:5.2f}')

    # Servise konacak model: TÜM veriyle eğitilir; raporlanan doğruluk = CV ortalaması
    final = make_clf().fit(X, y)
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'stego_model.joblib')
    joblib.dump({'model': final, 'accuracy': round(cv_acc*100, 2),
                 'train_acc': round(tr_acc*100, 2), 'test_acc': round(te_acc*100, 2),
                 'features': FEATURE_NAMES, 'n_covers': len(covers)}, out)
    print(f'\nKaydedildi: {out}  (rapor dogrulugu = CV %{cv_acc*100:.2f})')

if __name__ == '__main__':
    main()
