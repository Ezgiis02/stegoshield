/* ==========================================================================
   StegoShield Core Logic - Steganography & Steganalysis Suite
   ========================================================================== */

// Global state
let originalImage = null;
let stegoImage = null;
let analyzedImage = null;
let originalImageData = null;
let stegoImageData = null;
let analyzedImageData = null;

// Protocol constants
const MAGIC_BYTES = [83, 84, 71]; // ASCII: "STG"
const CHANNEL_CODES = { rgb: 0, r: 1, g: 2, b: 3 };
const CHANNEL_NAMES = { rgb: 'Tüm Kanallar (RGB)', r: 'Kırmızı (R)', g: 'Yeşil (G)', b: 'Mavi (B)' };

/* ==========================================================================
   Toast Notification System
   ========================================================================== */

function showToast(type, title, message, duration = 4500) {
    const container = document.getElementById('toast-container');
    const icons = { success: '✓', error: '✕', warning: '⚠', info: 'ℹ' };

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
        <span class="toast-icon">${icons[type] ?? 'ℹ'}</span>
        <div class="toast-body">
            <span class="toast-title">${title}</span>
            <span class="toast-message">${message}</span>
        </div>
        <button class="toast-close" onclick="dismissToast(this.parentElement)">✕</button>
    `;
    container.appendChild(toast);

    requestAnimationFrame(() => requestAnimationFrame(() => toast.classList.add('toast-show')));

    toast._timer = setTimeout(() => dismissToast(toast), duration);
}

function dismissToast(toast) {
    if (!toast || !toast.parentElement) return;
    clearTimeout(toast._timer);
    toast.classList.remove('toast-show');
    toast.classList.add('toast-hide');
    setTimeout(() => toast.remove(), 350);
}

/* ==========================================================================
   Tab Navigation
   ========================================================================== */

function switchTab(tabName) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
    document.getElementById(`section-${tabName}`).classList.add('active');
    document.getElementById(`tab-${tabName}`).classList.add('active');
    if (tabName === 'analyze' && analyzedImage) setTimeout(runAnalysis, 100);
}

/* ==========================================================================
   UI Helpers
   ========================================================================== */

function togglePasswordVisibility(inputId) {
    const input = document.getElementById(inputId);
    const button = input.nextElementSibling;
    if (input.type === 'password') {
        input.type = 'text';
        button.textContent = 'Gizle';
    } else {
        input.type = 'password';
        button.textContent = 'Göster';
    }
}

function setButtonLoading(btn, isLoading, loadingText = 'İşleniyor...') {
    if (isLoading) {
        btn._originalHTML = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = `<span class="spinner"></span>${loadingText}`;
    } else {
        btn.disabled = false;
        if (btn._originalHTML) btn.innerHTML = btn._originalHTML;
    }
}

/* ==========================================================================
   Cryptographic Module: RC4 Stream Cipher
   ========================================================================== */

function rc4(key, bytes) {
    const s = Array.from({ length: 256 }, (_, i) => i);
    let j = 0, x;
    for (let i = 0; i < 256; i++) {
        j = (j + s[i] + key.charCodeAt(i % key.length)) % 256;
        x = s[i]; s[i] = s[j]; s[j] = x;
    }
    let i = 0; j = 0;
    const out = new Uint8Array(bytes.length);
    for (let y = 0; y < bytes.length; y++) {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        x = s[i]; s[i] = s[j]; s[j] = x;
        out[y] = bytes[y] ^ s[(s[i] + s[j]) % 256];
    }
    return out;
}

/* ==========================================================================
   Steganography Protocol
   Packet: [MAGIC "STG" (3B)] + [FLAGS (1B): bit0=encrypt, bits1-2=channel] + [LENGTH big-endian (4B)] + [PAYLOAD]
   Channel codes: 0=RGB, 1=R, 2=G, 3=B  (stored in bits 2-1 of FLAGS byte)
   ========================================================================== */

function packPayload(messageText, passcode, channel) {
    const encoder = new TextEncoder();
    let payloadBytes = encoder.encode(messageText);
    const encryptFlag = (passcode && passcode.trim() !== '') ? 1 : 0;

    if (encryptFlag) payloadBytes = rc4(passcode, payloadBytes);

    const channelCode = CHANNEL_CODES[channel] ?? 0;
    const flags = (channelCode << 1) | encryptFlag;

    const packet = new Uint8Array(3 + 1 + 4 + payloadBytes.length);
    packet[0] = MAGIC_BYTES[0];
    packet[1] = MAGIC_BYTES[1];
    packet[2] = MAGIC_BYTES[2];
    packet[3] = flags;
    const len = payloadBytes.length;
    packet[4] = (len >>> 24) & 0xFF;
    packet[5] = (len >>> 16) & 0xFF;
    packet[6] = (len >>> 8)  & 0xFF;
    packet[7] =  len         & 0xFF;
    packet.set(payloadBytes, 8);
    return packet;
}

function bytesToBits(byteArray) {
    const bits = new Uint8Array(byteArray.length * 8);
    for (let i = 0; i < byteArray.length; i++) {
        for (let b = 0; b < 8; b++) bits[i * 8 + b] = (byteArray[i] >>> (7 - b)) & 1;
    }
    return bits;
}

function bitsToBytes(bitArray) {
    const bytes = new Uint8Array(Math.floor(bitArray.length / 8));
    for (let i = 0; i < bytes.length; i++) {
        let byte = 0;
        for (let b = 0; b < 8; b++) byte = (byte << 1) | bitArray[i * 8 + b];
        bytes[i] = byte;
    }
    return bytes;
}

/**
 * Reads `bitCount` LSBs from pixels using the given channel strategy.
 * RGB mode: 3 bits per pixel (R, G, B sequentially).
 * Single channel: 1 bit per pixel from that channel only.
 */
function readBitsInChannel(pixels, bitCount, channel) {
    const bits = new Uint8Array(bitCount);
    let bp = 0;
    if (channel === 'rgb') {
        for (let i = 0; i < pixels.length && bp < bitCount; i += 4)
            for (let c = 0; c < 3 && bp < bitCount; c++)
                bits[bp++] = pixels[i + c] & 1;
    } else {
        const offset = channel === 'g' ? 1 : channel === 'b' ? 2 : 0;
        for (let i = 0; i < pixels.length && bp < bitCount; i += 4)
            bits[bp++] = pixels[i + offset] & 1;
    }
    return bits;
}

/* ==========================================================================
   File Drop & Drag Listeners
   ========================================================================== */

function setupDragDrop(zoneId, inputId, infoId, callback) {
    const zone = document.getElementById(zoneId);
    const input = document.getElementById(inputId);

    zone.addEventListener('click', () => input.click());
    zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.classList.add('dragover'); });
    zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));
    zone.addEventListener('drop', (e) => {
        e.preventDefault();
        zone.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) handleFileSelect(e.dataTransfer.files[0], infoId, callback);
    });
    input.addEventListener('change', () => {
        if (input.files.length > 0) handleFileSelect(input.files[0], infoId, callback);
    });
}

function handleFileSelect(file, infoId, callback) {
    document.getElementById(infoId).style.display = 'block';
    document.getElementById(infoId).textContent = `✓  ${file.name}  (${(file.size / 1024).toFixed(1)} KB)`;
    const reader = new FileReader();
    reader.onload = (e) => { const img = new Image(); img.onload = () => callback(img); img.src = e.target.result; };
    reader.readAsDataURL(file);
}

document.addEventListener('DOMContentLoaded', () => {

    // ── Encode Tab ──────────────────────────────────────────────────────────
    setupDragDrop('drop-encode', 'file-encode', 'info-encode', (img) => {
        originalImage = img;
        const canvas = document.getElementById('canvas-original-encode');
        const ctx = canvas.getContext('2d');
        canvas.width = img.width; canvas.height = img.height;
        ctx.drawImage(img, 0, 0);
        originalImageData = ctx.getImageData(0, 0, img.width, img.height);

        document.getElementById('placeholder-orig-encode').style.display = 'none';
        ['msg-encode', 'pass-encode', 'channel-encode', 'btn-encode-action'].forEach(id => {
            document.getElementById(id).disabled = false;
        });

        const cs = document.getElementById('canvas-stego-encode');
        cs.getContext('2d').clearRect(0, 0, cs.width, cs.height);
        document.getElementById('placeholder-stego-encode').style.display = 'flex';
        document.getElementById('btn-download-stego').style.display = 'none';
        document.getElementById('encode-stats').style.display = 'none';
        updateCapacityStats();

        showToast('info', 'Görsel Yüklendi', `${img.width}×${img.height} piksel (${(img.width * img.height * 3 / 8 / 1024).toFixed(0)} KB maks. kapasite).`);
    });

    // ── Decode Tab ──────────────────────────────────────────────────────────
    setupDragDrop('drop-decode', 'file-decode', 'info-decode', (img) => {
        stegoImage = img;
        const canvas = document.getElementById('canvas-stego-decode');
        const ctx = canvas.getContext('2d');
        canvas.width = img.width; canvas.height = img.height;
        ctx.drawImage(img, 0, 0);
        stegoImageData = ctx.getImageData(0, 0, img.width, img.height);

        document.getElementById('placeholder-stego-decode').style.display = 'none';
        document.getElementById('pass-decode').disabled = false;
        document.getElementById('btn-decode-action').disabled = false;
        document.getElementById('msg-decode').value = '';
        document.getElementById('btn-copy-msg').style.display = 'none';
        document.getElementById('decode-meta').style.display = 'none';

        showToast('info', 'Stego Görsel Yüklendi', `${img.width}×${img.height} piksel — çözmeye hazır.`);
    });

    // ── Analyze Tab ─────────────────────────────────────────────────────────
    setupDragDrop('drop-analyze', 'file-analyze', 'info-analyze', (img) => {
        analyzedImage = img;
        const offscreen = document.createElement('canvas');
        offscreen.width = img.width; offscreen.height = img.height;
        const ctx = offscreen.getContext('2d');
        ctx.drawImage(img, 0, 0);
        analyzedImageData = ctx.getImageData(0, 0, img.width, img.height);

        document.getElementById('placeholder-analysis-lsb').style.display = 'none';
        document.getElementById('analysis-results').style.display = 'flex';
        document.getElementById('analysis-controls-box').style.display = 'flex';
        document.getElementById('placeholder-histogram').style.display = 'none';

        runAnalysis();
        runSignatureDetection();
        renderHistogram(analyzedImageData);
        showToast('info', 'Analiz Başlatıldı', `${img.width}×${img.height} piksel taranıyor.`);
    });

    // Live capacity updates
    document.getElementById('msg-encode').addEventListener('input', updateCapacityStats);
    document.getElementById('pass-encode').addEventListener('input', updateCapacityStats);
    document.getElementById('channel-encode').addEventListener('change', updateCapacityStats);
});

/* ==========================================================================
   Capacity Stats
   ========================================================================== */

function updateCapacityStats() {
    if (!originalImage) return;

    const message  = document.getElementById('msg-encode').value;
    const channel  = document.getElementById('channel-encode').value;
    const pixelCount = originalImage.width * originalImage.height;
    const maxBits  = pixelCount * (channel === 'rgb' ? 3 : 1);
    const reqBits  = 64 + new TextEncoder().encode(message).length * 8;
    const percent  = Math.min(100, (reqBits / maxBits) * 100);

    document.getElementById('encode-stats').style.display = 'flex';
    document.getElementById('stat-req-bits').textContent  = reqBits.toLocaleString('tr-TR') + ' bit';
    document.getElementById('stat-max-bits').textContent  = maxBits.toLocaleString('tr-TR') + ' bit';
    document.getElementById('stat-percent').textContent   = percent.toFixed(2) + '%';

    const bar = document.getElementById('capacity-bar-fill');
    bar.style.width  = percent + '%';
    bar.style.background = percent > 90 ? 'var(--danger)' : percent > 60 ? 'var(--warning)' : 'var(--primary)';

    const actionBtn = document.getElementById('btn-encode-action');
    if (reqBits > maxBits) {
        document.getElementById('stat-percent').style.color = 'var(--danger)';
        actionBtn.disabled = true;
        actionBtn.innerHTML = `<svg viewBox="0 0 24 24" class="btn-icon"><path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z" fill="currentColor"/></svg> Kapasite Aşıldı`;
    } else {
        document.getElementById('stat-percent').style.color = 'var(--primary)';
        actionBtn.disabled = false;
        actionBtn.innerHTML = `<svg viewBox="0 0 24 24" class="btn-icon"><path d="M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zM9 6c0-1.66 1.34-3 3-3s3 1.34 3 3v2H9V6zm9 14H6V10h12v10zm-6-3c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2z" fill="currentColor"/></svg> Mesajı Görsele Gizle`;
    }
}

/* ==========================================================================
   Encoding
   ========================================================================== */

function handleEncode() {
    if (!originalImage || !originalImageData) {
        showToast('error', 'Görsel Eksik', 'Lütfen önce bir taşıyıcı görsel yükleyin.'); return;
    }
    const message  = document.getElementById('msg-encode').value;
    const passcode = document.getElementById('pass-encode').value;
    const channel  = document.getElementById('channel-encode').value;

    if (!message.trim()) {
        showToast('warning', 'Mesaj Eksik', 'Lütfen gizlemek istediğiniz mesajı girin.'); return;
    }

    const btn = document.getElementById('btn-encode-action');
    setButtonLoading(btn, true, 'Gizleniyor...');

    setTimeout(() => {
        try {
            const packet    = packPayload(message, passcode, channel);
            const bitStream = bytesToBits(packet);

            const { width, height } = originalImage;
            const canvasStego = document.getElementById('canvas-stego-encode');
            canvasStego.width = width; canvasStego.height = height;
            const ctxStego = canvasStego.getContext('2d');

            const imgData = ctxStego.createImageData(width, height);
            imgData.data.set(originalImageData.data);
            const pixels = imgData.data;

            let bp = 0;
            const bLen = bitStream.length;

            if (channel === 'rgb') {
                for (let i = 0; i < pixels.length && bp < bLen; i += 4)
                    for (let c = 0; c < 3 && bp < bLen; c++)
                        pixels[i + c] = (pixels[i + c] & 0xFE) | bitStream[bp++];
            } else {
                const offset = channel === 'g' ? 1 : channel === 'b' ? 2 : 0;
                for (let i = 0; i < pixels.length && bp < bLen; i += 4)
                    pixels[i + offset] = (pixels[i + offset] & 0xFE) | bitStream[bp++];
            }

            ctxStego.putImageData(imgData, 0, 0);
            document.getElementById('placeholder-stego-encode').style.display = 'none';
            document.getElementById('btn-download-stego').style.display = 'flex';

            renderDiffMap(originalImageData.data, imgData.data, width, height);

            const encLabel = (passcode && passcode.trim()) ? 'RC4 şifreli' : 'şifresiz';
            showToast('success', 'Gizleme Tamamlandı!',
                `${message.length} karakter, ${CHANNEL_NAMES[channel]} kanalına ${encLabel} olarak yazıldı.`);
        } catch (e) {
            showToast('error', 'Hata Oluştu', e.message);
        } finally {
            setButtonLoading(btn, false);
            updateCapacityStats();
        }
    }, 50);
}

function renderDiffMap(origData, stegoData, width, height) {
    const section = document.getElementById('diff-section');
    const canvas  = document.getElementById('canvas-diff-encode');
    canvas.width  = width;
    canvas.height = height;
    const ctx     = canvas.getContext('2d');
    const diff    = ctx.createImageData(width, height);

    let changedPixels = 0;
    let changedBits   = 0;

    for (let i = 0; i < origData.length; i += 4) {
        const dR = Math.abs(stegoData[i]   - origData[i]);
        const dG = Math.abs(stegoData[i+1] - origData[i+1]);
        const dB = Math.abs(stegoData[i+2] - origData[i+2]);

        // Amplify to 255 so single-bit changes become visible
        diff.data[i]   = dR * 255;
        diff.data[i+1] = dG * 255;
        diff.data[i+2] = dB * 255;
        diff.data[i+3] = 255;

        if (dR || dG || dB) {
            changedPixels++;
            changedBits += (dR ? 1 : 0) + (dG ? 1 : 0) + (dB ? 1 : 0);
        }
    }

    ctx.putImageData(diff, 0, 0);
    section.style.display = 'block';

    const totalPixels = width * height;
    const coveragePct = (changedPixels / totalPixels * 100).toFixed(2);

    document.getElementById('diff-stats').innerHTML = `
        <div class="diff-stat"><span>Değiştirilen Piksel</span><strong>${changedPixels.toLocaleString('tr-TR')}</strong></div>
        <div class="diff-stat"><span>Toplam Piksel</span><strong>${totalPixels.toLocaleString('tr-TR')}</strong></div>
        <div class="diff-stat"><span>Kaplama Oranı</span><strong>${coveragePct}%</strong></div>
        <div class="diff-stat"><span>Yazılan Bit</span><strong>${changedBits.toLocaleString('tr-TR')}</strong></div>
    `;
}

function downloadStegoImage() {
    const canvas = document.getElementById('canvas-stego-encode');
    if (!canvas) return;
    const link = document.createElement('a');
    link.download = 'stegoshield_output.png';
    link.href = canvas.toDataURL('image/png');
    link.click();
    showToast('success', 'İndirme Başlatıldı', 'Stego görsel kayıpsız PNG formatında kaydedildi.');
}

/* ==========================================================================
   Decoding  —  Auto-detects channel from the packet header
   ========================================================================== */

function handleDecode() {
    if (!stegoImage || !stegoImageData) {
        showToast('error', 'Görsel Eksik', 'Lütfen önce çözümlenecek stego görseli yükleyin.'); return;
    }

    const passcode = document.getElementById('pass-decode').value;
    const pixels   = stegoImageData.data;
    const btn      = document.getElementById('btn-decode-action');
    setButtonLoading(btn, true, 'Çözülüyor...');

    setTimeout(() => {
        try {
            // Try all channel modes to find the correct StegoShield header
            let detectedChannel = null;
            let headerBytes     = null;

            for (const ch of ['rgb', 'r', 'g', 'b']) {
                const bytes = bitsToBytes(readBitsInChannel(pixels, 64, ch));
                if (bytes[0] === MAGIC_BYTES[0] && bytes[1] === MAGIC_BYTES[1] && bytes[2] === MAGIC_BYTES[2]) {
                    detectedChannel = ch;
                    headerBytes     = bytes;
                    break;
                }
            }

            if (!detectedChannel) {
                showToast('error', 'Geçersiz Görsel',
                    'Bu görselde StegoShield protokolü ile gizlenmiş geçerli bir veri bulunamadı. Yalnızca StegoShield ile oluşturulan kayıpsız PNG dosyaları desteklenir.');
                document.getElementById('msg-decode').value = 'ÇÖZME HATASI: Geçerli bir StegoShield imzası bulunamadı. Görsel farklı bir araçla oluşturulmuş veya kayıplı sıkıştırma uygulanmış olabilir.';
                return;
            }

            const flags       = headerBytes[3];
            const encryptFlag = flags & 1;
            const dataLength  = (headerBytes[4] << 24) | (headerBytes[5] << 16) | (headerBytes[6] << 8) | headerBytes[7];

            if (dataLength <= 0 || dataLength > pixels.length) {
                showToast('error', 'Bozuk Paket', 'Geçersiz paket boyutu. Dosya bozulmuş veya kayıplı sıkıştırmayla kaydedilmiş olabilir.');
                return;
            }

            // Read full payload using the detected channel
            const fullBytes = bitsToBytes(readBitsInChannel(pixels, 64 + dataLength * 8, detectedChannel));
            let payloadBytes = fullBytes.slice(8);

            if (encryptFlag) {
                if (!passcode || !passcode.trim()) {
                    showToast('warning', 'Parola Gerekli',
                        'Bu görseldeki mesaj RC4 ile şifrelenmiştir. Doğru parolayı girip tekrar deneyin.');
                    document.getElementById('msg-decode').value = '[ŞİFRELENMİŞ VERİ]: Bu mesaj parola ile korunmaktadır. Doğru parolayı girip tekrar deneyin.';
                    return;
                }
                payloadBytes = rc4(passcode, payloadBytes);
            }

            const decodedMessage = new TextDecoder().decode(payloadBytes);
            document.getElementById('msg-decode').value = decodedMessage;
            document.getElementById('btn-copy-msg').style.display = 'block';

            // Show metadata panel
            const meta = document.getElementById('decode-meta');
            meta.style.display = 'flex';
            document.getElementById('meta-channel').textContent  = CHANNEL_NAMES[detectedChannel];
            document.getElementById('meta-encrypt').textContent  = encryptFlag ? 'RC4 Şifreli' : 'Şifresiz';
            document.getElementById('meta-length').textContent   = `${dataLength.toLocaleString('tr-TR')} bayt`;

            showToast('success', 'Çözme Başarılı!',
                `${dataLength} bayt mesaj çözüldü. Kanal: ${CHANNEL_NAMES[detectedChannel]}${encryptFlag ? ' · RC4 şifreli' : ''}.`);
        } catch (e) {
            showToast('error', 'Çözme Hatası',
                'Mesaj çözümlenemedi. Parola yanlış olabilir veya görsel kayıplı sıkıştırma ile kaydedilmiş olabilir.');
            document.getElementById('msg-decode').value = 'ÇÖZME HATASI: Karakter kodlaması çözülemedi. Parola yanlış olabilir veya görsel bozulmuş olabilir.';
        } finally {
            setButtonLoading(btn, false);
        }
    }, 50);
}

async function copyDecodedMessage() {
    const text = document.getElementById('msg-decode').value;
    if (!text) return;
    try {
        await navigator.clipboard.writeText(text);
    } catch (_) {
        // Fallback for non-HTTPS environments
        document.getElementById('msg-decode').select();
        document.execCommand('copy');
    }
    showToast('success', 'Panoya Kopyalandı', 'Gizli mesaj başarıyla panoya kopyalandı.');
}

/* ==========================================================================
   Signature Detection — StegoShield Protocol
   ========================================================================== */

function runSignatureDetection() {
    const el = document.getElementById('signature-result');
    if (!el || !analyzedImageData) return;

    const pixels = analyzedImageData.data;

    // Try all channel modes for the 64-bit header
    for (const ch of ['rgb', 'r', 'g', 'b']) {
        const bytes = bitsToBytes(readBitsInChannel(pixels, 64, ch));
        if (bytes[0] === MAGIC_BYTES[0] && bytes[1] === MAGIC_BYTES[1] && bytes[2] === MAGIC_BYTES[2]) {
            const encryptFlag = bytes[3] & 1;
            const dataLength  = (bytes[4] << 24) | (bytes[5] << 16) | (bytes[6] << 8) | bytes[7];
            const channelName = CHANNEL_NAMES[ch];

            el.className = 'signature-box sig-detected';
            el.innerHTML = `
                <span class="sig-icon">⚠</span>
                <div class="sig-body">
                    <strong>StegoShield İmzası Tespit Edildi!</strong>
                    <span>Kanal: ${channelName} &nbsp;|&nbsp; ${encryptFlag ? 'RC4 Şifreli' : 'Şifresiz'} &nbsp;|&nbsp; Payload: ${dataLength.toLocaleString('tr-TR')} bayt</span>
                </div>`;
            return;
        }
    }

    el.className = 'signature-box sig-clean';
    el.innerHTML = `
        <span class="sig-icon">✓</span>
        <div class="sig-body">
            <strong>StegoShield İmzası Bulunamadı</strong>
            <span>Bu görsel StegoShield protokolüyle oluşturulmamış veya farklı bir araç kullanılmış.</span>
        </div>`;
}

/* ==========================================================================
   Steganalysis Module — Chi-Square + Visual LSB Map
   ========================================================================== */

function runAnalysis() {
    if (!analyzedImage || !analyzedImageData) return;

    const channelSelect = document.getElementById('analysis-channel').value;
    const blendFactor   = parseInt(document.getElementById('analysis-contrast').value) / 10;
    const { width, height } = analyzedImage;

    const canvasLsb = document.getElementById('canvas-analysis-lsb');
    canvasLsb.width = width; canvasLsb.height = height;
    const ctxLsb = canvasLsb.getContext('2d');

    const lsbImgData = ctxLsb.createImageData(width, height);
    const src  = analyzedImageData.data;
    const dest = lsbImgData.data;

    // Visual LSB map
    for (let i = 0; i < src.length; i += 4) {
        const r = src[i], g = src[i+1], b = src[i+2], a = src[i+3];
        const lR = (r & 1) * 255, lG = (g & 1) * 255, lB = (b & 1) * 255;
        let tR, tG, tB;
        if (channelSelect === 'rgb') { tR = lR; tG = lG; tB = lB; }
        else if (channelSelect === 'r') { tR = tG = tB = lR; }
        else if (channelSelect === 'g') { tR = tG = tB = lG; }
        else                            { tR = tG = tB = lB; }
        dest[i]   = tR * blendFactor + r * (1 - blendFactor);
        dest[i+1] = tG * blendFactor + g * (1 - blendFactor);
        dest[i+2] = tB * blendFactor + b * (1 - blendFactor);
        dest[i+3] = a;
    }
    ctxLsb.putImageData(lsbImgData, 0, 0);

    // Statistical analysis
    const fR = new Array(256).fill(0), fG = new Array(256).fill(0), fB = new Array(256).fill(0);
    let lsbOnes = 0, total = 0;
    for (let i = 0; i < src.length; i += 4) {
        fR[src[i]]++; fG[src[i+1]]++; fB[src[i+2]]++;
        lsbOnes += (src[i] & 1) + (src[i+1] & 1) + (src[i+2] & 1);
        total += 3;
    }

    let chi2 = 0, df = 0;
    for (let c = 0; c < 3; c++) {
        const f = c === 0 ? fR : c === 1 ? fG : fB;
        for (let k = 0; k < 128; k++) {
            const s = f[2*k] + f[2*k+1];
            if (s > 0) { chi2 += (f[2*k] - f[2*k+1]) ** 2 / s; df++; }
        }
    }

    let stegoProb = 0;
    if (df > 0) {
        const v = 2 / (9 * df);
        const z = (Math.pow(chi2 / df, 1/3) - (1 - v)) / Math.sqrt(v);
        stegoProb = 1 - normalCDF(z);
    }
    if (chi2 === 0) stegoProb = 1.0;

    const p1 = lsbOnes / total, p0 = 1 - p1;
    const entropy = (p0 > 0 && p1 > 0) ? -(p0 * Math.log2(p0) + p1 * Math.log2(p1)) : 0;

    // Update gauge
    const pct = Math.round(stegoProb * 100);
    document.getElementById('gauge-percentage').textContent = `${pct}%`;
    document.getElementById('gauge-fill-val').style.strokeDashoffset = 251.2 * (1 - pct / 100);

    let color, title, desc, cls;
    if (pct < 30) {
        color = 'var(--success)'; title = 'Görsel Temiz'; cls = 'status-clean';
        desc = 'İstatistiksel analizde herhangi bir LSB sapması tespit edilmedi. Görsel doğal görünüyor.';
    } else if (pct < 75) {
        color = 'var(--warning)'; title = 'Şüpheli Dağılım'; cls = 'status-warn';
        desc = 'Piksel bit dağılımında hafif anormallikler tespit edildi. Düşük yoğunluklu steganografi uygulanmış olabilir.';
    } else {
        color = 'var(--danger)'; title = 'Gizli Veri Tespit Edildi!'; cls = 'status-danger';
        desc = 'DİKKAT: LSB frekans anormalliği son derece yüksek! Bu görsele steganografi uygulanmış olma ihtimali çok yüksek.';
    }

    document.getElementById('gauge-fill-val').style.stroke = color;
    document.getElementById('gauge-percentage').style.color = color;
    const card = document.getElementById('analysis-status-card');
    card.className = `analysis-summary-card ${cls}`;
    document.getElementById('analysis-status-title').textContent = title;
    document.getElementById('analysis-status-desc').textContent  = desc;
    document.getElementById('metric-pvalue').textContent   = (1 - stegoProb).toFixed(6);
    document.getElementById('metric-entropy').textContent  = entropy.toFixed(4);
    document.getElementById('metric-lsb-mean').textContent = p1.toFixed(4);
}

function normalCDF(z) {
    const t = 1 / (1 + 0.2316419 * Math.abs(z));
    const d = 0.3989423 * Math.exp(-z * z / 2);
    const p = d * t * (0.3193815 + t * (-0.3565638 + t * (1.781478 + t * (-1.821256 + t * 1.330274))));
    return z > 0 ? 1 - p : p;
}

/* ==========================================================================
   Histogram Module
   ========================================================================== */

function renderHistogram(imgData) {
    const canvas = document.getElementById('canvas-histogram');
    if (!canvas) return;

    canvas.width  = canvas.clientWidth  * window.devicePixelRatio;
    canvas.height = canvas.clientHeight * window.devicePixelRatio;
    const ctx = canvas.getContext('2d');
    const W = canvas.width, H = canvas.height;

    ctx.fillStyle = '#0a0e17';
    ctx.fillRect(0, 0, W, H);
    ctx.strokeStyle = 'rgba(255,255,255,0.05)';
    ctx.lineWidth = 1;
    for (let i = 1; i < 5; i++) { ctx.beginPath(); ctx.moveTo(W/5*i, 0); ctx.lineTo(W/5*i, H); ctx.stroke(); }
    for (let i = 1; i < 4; i++) { ctx.beginPath(); ctx.moveTo(0, H/4*i); ctx.lineTo(W, H/4*i); ctx.stroke(); }

    const rH = new Array(256).fill(0), gH = new Array(256).fill(0), bH = new Array(256).fill(0);
    const px = imgData.data;
    for (let i = 0; i < px.length; i += 4) { rH[px[i]]++; gH[px[i+1]]++; bH[px[i+2]]++; }

    const maxVal = Math.max(...rH, ...gH, ...bH);
    if (maxVal === 0) return;

    drawChannelCurve(ctx, rH, maxVal, W, H, 'rgba(255,23,68,0.4)',   'rgba(255,23,68,1)');
    drawChannelCurve(ctx, gH, maxVal, W, H, 'rgba(0,230,118,0.4)',   'rgba(0,230,118,1)');
    drawChannelCurve(ctx, bH, maxVal, W, H, 'rgba(0,229,255,0.4)',   'rgba(0,229,255,1)');
}

function drawChannelCurve(ctx, hist, maxVal, W, H, fillColor, strokeColor) {
    ctx.beginPath();
    ctx.moveTo(0, H);
    const step = W / 256;
    for (let i = 0; i < 256; i++) ctx.lineTo(i * step, H - (hist[i] / maxVal) * (H - 15) - 4);
    ctx.lineTo(W, H);
    ctx.closePath();
    ctx.fillStyle   = fillColor;   ctx.fill();
    ctx.strokeStyle = strokeColor; ctx.lineWidth = 1.5; ctx.stroke();
}
