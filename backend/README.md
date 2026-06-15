# StegoShield ML Backend

Arka planda çalışan steganaliz modeli. Web arayüzünden gelen görseli alır, güçlü
LSB özelliklerini (Chi-Square, RS, LSB entropisi/ortalaması, blok-Chi) çıkarır ve
gerçek görsellerle eğitilmiş **Random Forest** ile "stego/temiz" tahmini döner.

## Kurulum

```bash
pip install -r requirements.txt
```

## Çalıştırma

```bash
python app.py          # http://localhost:5000
```

Sunucu açıldığında web arayüzündeki **Analiz** sekmesi otomatik olarak
`http://localhost:5000/predict` adresine görseli gönderir ve "ML Tahmini"
panelinde sonucu gösterir.

## Dosyalar

| Dosya | Açıklama |
|-------|----------|
| `app.py` | Flask sunucusu (`/predict`, `/health`) |
| `features.py` | Özellik çıkarımı + LSB gömme (eğitim ve tahminde ortak) |
| `train_model.py` | Gerçek görsellerden temiz/stego veri üretip modeli eğitir |
| `eval_leakage.py` | Overfitting + veri sızıntısı (data leakage) denetimi |
| `stego_model.joblib` | Eğitilmiş model (CV doğruluğu ~%86) |

## Model

- **Özellikler (5):** Chi2 olasılığı, RS oranı, LSB entropisi, LSB ortalaması, blok-Chi maksimumu
- **Eğitim:** 180 gerçek görsel × {temiz, stego} = 360 örnek
- **Doğrulama:** GroupKFold 5-kat (aynı kapağın iki sürümü aynı tarafta → veri sızıntısı yok)
- **Doğruluk:** ~%86 (CV), hafif overfit (Train %92 / Test %84)

> Not: Model doğal/dokulu görseller için ayarlıdır. Çok düşük kaplama oranlı
> dağıtık mesajları istatistiksel/ML yöntemler kaçırabilir; bu durumda protokol
> imza taraması kesin tespit sağlar.
