# -*- coding: utf-8 -*-
"""
StegoShield ML Backend
Arka planda çalışan steganaliz modeli. Web uygulamasından gelen görseli alır,
güçlü LSB özelliklerini (chi-square, RS, LSB entropisi/ortalaması, blok-chi)
çıkarır, gerçek görsellerle eğitilmiş Random Forest ile "stego/temiz" tahmini
yapar ve sonucu JSON olarak döner.

Önce:  python train_model.py   (stego_model.joblib üretir)
Sonra: python app.py           (http://localhost:5000)
"""
import os
import numpy as np
import cv2
import joblib
from flask import Flask, request, jsonify

from features import extract_lsb_features, FEATURE_NAMES

app = Flask(__name__)

@app.after_request
def add_cors(resp):
    resp.headers['Access-Control-Allow-Origin'] = '*'
    resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    resp.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return resp

# ── Eğitilmiş modeli yükle ─────────────────────────────────────────────────
BASE = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE, 'stego_model.joblib')
bundle = joblib.load(MODEL_PATH)
clf = bundle['model']
ACCURACY = bundle['accuracy']
N_COVERS = bundle.get('n_covers', '?')
print(f'Model yuklendi. Test dogrulugu: %{ACCURACY}  ({N_COVERS} kapak gorseli ile egitildi)')

def imdecode_unicode(file_storage):
    data = np.frombuffer(file_storage.read(), np.uint8)
    return cv2.imdecode(data, cv2.IMREAD_COLOR)

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok', 'model': 'RandomForest', 'accuracy': ACCURACY,
                    'features': FEATURE_NAMES, 'trained_on': N_COVERS})

@app.route('/predict', methods=['POST', 'OPTIONS'])
def predict():
    if request.method == 'OPTIONS':
        return ('', 204)
    if 'image' not in request.files:
        return jsonify({'error': 'Görsel bulunamadı (form-data "image" bekleniyor).'}), 400

    img = imdecode_unicode(request.files['image'])
    if img is None:
        return jsonify({'error': 'Görsel çözülemedi.'}), 400

    feats = extract_lsb_features(img)
    proba = float(clf.predict_proba([feats])[0][1])  # stego (1) olasılığı
    label = 'stego' if proba >= 0.5 else 'clean'

    return jsonify({
        'label': label,
        'stego_probability': round(proba * 100, 2),
        'features': dict(zip(FEATURE_NAMES, [round(f, 4) for f in feats])),
        'model_accuracy': ACCURACY,
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
