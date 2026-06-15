# -*- coding: utf-8 -*-
"""
Overfitting + data leakage denetimi.
Aynı kapak görselinin temiz+stego sürümleri aynı gruba aittir. Rastgele bölme
bu çiftleri train/test'e dağıtıp leakage'a yol açabilir. GroupKFold ile dürüst
sonucu karşılaştırırız; ayrıca train-test doğruluk farkıyla overfit'i ölçeriz.
"""
import os, glob
import numpy as np
import cv2
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupShuffleSplit, GroupKFold, train_test_split
from sklearn.metrics import accuracy_score
from features import extract_lsb_features, embed_lsb

COVER_DIR = r'C:\Users\ezgis\Pictures\Screenshots'
MAX_IMAGES = 180
EMBED_RATES = [0.25, 0.5, 0.75, 1.0]

def rd(p):
    try: return cv2.imdecode(np.fromfile(p, dtype=np.uint8), cv2.IMREAD_COLOR)
    except Exception: return None

def build():
    paths = sorted(glob.glob(os.path.join(COVER_DIR, '*.png')) + glob.glob(os.path.join(COVER_DIR, '*.jpg')))
    rng0 = np.random.default_rng(7); rng0.shuffle(paths)
    rng = np.random.default_rng(42)
    X, y, groups = [], [], []
    g = 0
    for p in paths:
        img = rd(p)
        if img is None or min(img.shape[:2]) < 64: continue
        X.append(extract_lsb_features(img)); y.append(0); groups.append(g)
        stego = embed_lsb(img, float(rng.choice(EMBED_RATES)), rng)
        X.append(extract_lsb_features(stego)); y.append(1); groups.append(g)
        g += 1
        if g >= MAX_IMAGES: break
    return np.array(X), np.array(y), np.array(groups)

def new_clf():
    return RandomForestClassifier(n_estimators=200, max_depth=12, min_samples_split=4, random_state=42)

print('Ozellikler cikariliyor...')
X, y, groups = build()
print(f'  {len(y)} ornek, {len(set(groups))} kapak grubu\n')

# A) RASTGELE bölme (mevcut yöntem — leakage riski)
Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
clf = new_clf().fit(Xtr, ytr)
print('A) RASTGELE bolme (leakage riskli):')
print(f'   Train dogruluk: %{accuracy_score(ytr, clf.predict(Xtr))*100:.2f}')
print(f'   Test  dogruluk: %{accuracy_score(yte, clf.predict(Xte))*100:.2f}')

# B) GRUPLU bölme (aynı kapak aynı tarafta — dürüst)
gss = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=42)
tr_i, te_i = next(gss.split(X, y, groups))
clf2 = new_clf().fit(X[tr_i], y[tr_i])
print('\nB) GRUPLU bolme (dürüst, ayni kapak ayni tarafta):')
print(f'   Train dogruluk: %{accuracy_score(y[tr_i], clf2.predict(X[tr_i]))*100:.2f}')
print(f'   Test  dogruluk: %{accuracy_score(y[te_i], clf2.predict(X[te_i]))*100:.2f}')

# C) GroupKFold 5-kat çapraz doğrulama (en güvenilir tahmin)
gkf = GroupKFold(n_splits=5)
accs = []
for tr, te in gkf.split(X, y, groups):
    c = new_clf().fit(X[tr], y[tr])
    accs.append(accuracy_score(y[te], c.predict(X[te])))
print('\nC) GroupKFold 5-kat capraz dogrulama:')
print(f'   Kat dogruluklari: {[f"%{a*100:.1f}" for a in accs]}')
print(f'   Ortalama: %{np.mean(accs)*100:.2f}  (+/- %{np.std(accs)*100:.2f})')

print('\nYORUM:')
print('  - A ile B test dogruluklari yakinsa  -> leakage YOK.')
print('  - Train ~%100 ve Test cok dusukse     -> overfit var.')
print('  - C ortalamasi gercek genelleme gucudur.')
