/* ==========================================================================
   StegoShield Core Logic - Steganography & Steganalysis Suite (v2)
   Güvenli sürüm: AES-256-GCM + PBKDF2, dağıtık (PRNG) gömme, bütünlük kontrolü,
   blok bazlı chi-square ve Web Worker tabanlı steganaliz.
   ========================================================================== */

// Global state
let originalImage = null;
let stegoImage = null;
let analyzedImage = null;
let originalImageData = null;
let stegoImageData = null;
let analyzedImageData = null;
let originalFileName = '';
let analyzedFile = null;                       // ML backend'e gönderilecek ham dosya
const ML_BACKEND = 'http://localhost:5000';    // Python steganaliz sunucusu

// Nihai karar için her yöntemin son sonucu
let verdictState = { sig: null, chi: null, rs: null, ml: null };

// Protocol constants
const MAGIC_BYTES   = [83, 84, 71]; // ASCII: "STG"
const CHANNEL_CODES = { rgb: 0, r: 1, g: 2, b: 3 };
const CHANNEL_NAMES = { rgb: 'Tüm Kanallar (RGB)', r: 'Kırmızı (R)', g: 'Yeşil (G)', b: 'Mavi (B)' };
const DEPTH_NAMES   = { 1: 'LSB-1 (Standart)', 2: 'LSB-2 (2× kapasite)', 3: 'LSB-3 (3× kapasite)' };

// Yeni paket başlığı (toplam 40 bayt / 320 bit):
//   [0..2]   Magic "STG"
//   [3]      Flags:  bit0=encrypt, bits1-2=channel(0-3), bits3-4=depth-1(0-2)
//   [4..19]  Salt (16B, PBKDF2 için — şifresizse sıfır)
//   [20..31] IV   (12B, AES-GCM için — şifresizse sıfır)
//   [32..35] Checksum (SHA-256(plaintext)[0:4] — bütünlük kontrolü)
//   [36..39] Payload uzunluğu (big-endian)
//   [40..]   Payload (şifreliyse AES-GCM ciphertext+tag, değilse UTF-8 düz metin)
const HEADER_BYTES = 40;
const HEADER_BITS  = HEADER_BYTES * 8;

// Dağıtık gömme için sabit PRNG tohumu. Gizlilik AES katmanında sağlanır;
// yayılım, kör (blind) steganalize karşı istatistiksel izi tüm görsele dağıtmak içindir.
const SPREAD_SEED  = 0x53544730; // "STG0"
const PBKDF2_ITERS = 100000;

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
    if (input.type === 'password') { input.type = 'text';  button.textContent = 'Gizle'; }
    else                           { input.type = 'password'; button.textContent = 'Göster'; }
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
   Cryptographic Module — AES-256-GCM + PBKDF2 (Web Crypto API)
   ========================================================================== */

async function deriveKey(password, salt) {
    const baseKey = await crypto.subtle.importKey(
        'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: PBKDF2_ITERS, hash: 'SHA-256' },
        baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function sha256(bytes) {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

function bytesEqual(a, b, len) {
    for (let i = 0; i < len; i++) if (a[i] !== b[i]) return false;
    return true;
}

/* ==========================================================================
   Steganography Protocol — packet build / parse
   ========================================================================== */

async function packPayload(messageText, passcode, channel, depth) {
    const plain      = new TextEncoder().encode(messageText);
    const checksum   = (await sha256(plain)).slice(0, 4);
    const encryptFlag = (passcode && passcode.trim() !== '') ? 1 : 0;

    let salt = new Uint8Array(16), iv = new Uint8Array(12), payload = plain;
    if (encryptFlag) {
        salt = crypto.getRandomValues(new Uint8Array(16));
        iv   = crypto.getRandomValues(new Uint8Array(12));
        const key = await deriveKey(passcode, salt);
        const ct  = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain);
        payload   = new Uint8Array(ct); // ciphertext + 16B GCM tag
    }

    const channelCode = CHANNEL_CODES[channel] ?? 0;
    const flags = (encryptFlag) | (channelCode << 1) | ((depth - 1) << 3);

    const packet = new Uint8Array(HEADER_BYTES + payload.length);
    packet[0] = MAGIC_BYTES[0]; packet[1] = MAGIC_BYTES[1]; packet[2] = MAGIC_BYTES[2];
    packet[3] = flags;
    packet.set(salt, 4);
    packet.set(iv, 20);
    packet.set(checksum, 32);
    const len = payload.length;
    packet[36] = (len >>> 24) & 0xFF; packet[37] = (len >>> 16) & 0xFF;
    packet[38] = (len >>> 8)  & 0xFF; packet[39] =  len         & 0xFF;
    packet.set(payload, HEADER_BYTES);
    return packet;
}

function bytesToBits(byteArray) {
    const bits = new Uint8Array(byteArray.length * 8);
    for (let i = 0; i < byteArray.length; i++)
        for (let b = 0; b < 8; b++) bits[i * 8 + b] = (byteArray[i] >>> (7 - b)) & 1;
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

/* ==========================================================================
   Distributed Embedding — seeded PRNG spreads bits across the whole image
   ========================================================================== */

function mulberry32(a) {
    return function () {
        a |= 0; a = (a + 0x6D2B79F5) | 0;
        let t = Math.imul(a ^ (a >>> 15), 1 | a);
        t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
}

function totalSlots(channel, depth, pixelCount) {
    return pixelCount * (channel === 'rgb' ? 3 : 1) * depth;
}

/* Sparse partial Fisher-Yates: deterministic first `count` slots of a seeded
   shuffle of [0..total-1]. O(count) memory; prefix-consistent for any count. */
function spreadOrder(total, count, seed) {
    const rng = mulberry32(seed);
    const map = new Map();
    const out = new Int32Array(count);
    for (let i = 0; i < count; i++) {
        const j  = i + Math.floor(rng() * (total - i)); // i..total-1
        const vi = map.has(i) ? map.get(i) : i;
        const vj = map.has(j) ? map.get(j) : j;
        out[i] = vj;
        map.set(j, vi);
    }
    return out;
}

/* Map a slot index back to (byteOffset, bitPosition). */
function slotToByteBit(slot, channel, depth) {
    const dpos = slot % depth;
    let rest = (slot - dpos) / depth;
    let off;
    if (channel === 'rgb') {
        const c = rest % 3;
        const p = (rest - c) / 3;
        off = p * 4 + c;
    } else {
        off = rest * 4 + (channel === 'g' ? 1 : channel === 'b' ? 2 : 0);
    }
    return [off, depth - 1 - dpos];
}

function writeBitsToPixels(pixels, bitStream, channel, depth) {
    const n     = pixels.length / 4;
    const total = totalSlots(channel, depth, n);
    const order = spreadOrder(total, bitStream.length, SPREAD_SEED);
    for (let k = 0; k < bitStream.length; k++) {
        const [off, bp] = slotToByteBit(order[k], channel, depth);
        pixels[off] = (pixels[off] & ~(1 << bp)) | (bitStream[k] << bp);
    }
}

function readBitsFromPixels(pixels, bitCount, channel, depth) {
    const n     = pixels.length / 4;
    const total = totalSlots(channel, depth, n);
    if (total < bitCount) return null;
    const order = spreadOrder(total, bitCount, SPREAD_SEED);
    const bits  = new Uint8Array(bitCount);
    for (let k = 0; k < bitCount; k++) {
        const [off, bp] = slotToByteBit(order[k], channel, depth);
        bits[k] = (pixels[off] >> bp) & 1;
    }
    return bits;
}

/* ==========================================================================
   File Drop & Drag Listeners
   ========================================================================== */

function setupDragDrop(zoneId, inputId, infoId, callback) {
    const zone  = document.getElementById(zoneId);
    const input = document.getElementById(inputId);
    zone.addEventListener('click', () => input.click());
    zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('dragover'); });
    zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));
    zone.addEventListener('drop', e => {
        e.preventDefault(); zone.classList.remove('dragover');
        if (e.dataTransfer.files.length > 0) handleFileSelect(e.dataTransfer.files[0], infoId, callback);
    });
    input.addEventListener('change', () => {
        if (input.files.length > 0) handleFileSelect(input.files[0], infoId, callback);
    });
}

function handleFileSelect(file, infoId, callback) {
    if (infoId === 'info-encode') originalFileName = file.name;
    if (infoId === 'info-analyze') analyzedFile = file;
    document.getElementById(infoId).style.display = 'block';
    document.getElementById(infoId).textContent = `✓  ${file.name}  (${(file.size / 1024).toFixed(1)} KB)`;
    const reader = new FileReader();
    reader.onload = e => { const img = new Image(); img.onload = () => callback(img); img.src = e.target.result; };
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
        ['msg-encode', 'pass-encode', 'channel-encode', 'depth-encode', 'btn-encode-action'].forEach(id => {
            const el = document.getElementById(id); if (el) el.disabled = false;
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

        verdictState = { sig: null, chi: null, rs: null, ml: null };
        runSignatureDetection();
        runAnalysis();
        runHeavyAnalysis();        // RS + blok chi-square (Web Worker)
        runMLPrediction();         // Sunucudaki ML modeli (Python backend)
        renderHistogram(analyzedImageData);
        showToast('info', 'Analiz Başlatıldı', `${img.width}×${img.height} piksel taranıyor.`);
    });

    // Live capacity updates
    ['msg-encode', 'pass-encode'].forEach(id =>
        document.getElementById(id).addEventListener('input', updateCapacityStats));
    document.getElementById('channel-encode').addEventListener('change', updateCapacityStats);
    document.getElementById('depth-encode').addEventListener('change', updateCapacityStats);
});

/* ==========================================================================
   Capacity Stats
   ========================================================================== */

function updateCapacityStats() {
    if (!originalImage) return;
    const message    = document.getElementById('msg-encode').value;
    const passcode   = document.getElementById('pass-encode').value;
    const channel    = document.getElementById('channel-encode').value;
    const depth      = parseInt(document.getElementById('depth-encode').value) || 1;
    const pixelCount = originalImage.width * originalImage.height;
    const maxBits    = pixelCount * (channel === 'rgb' ? 3 : 1) * depth;

    const msgBytes   = new TextEncoder().encode(message).length;
    const encrypted  = passcode && passcode.trim() !== '';
    const payloadLen = msgBytes + (encrypted ? 16 : 0); // GCM tag
    const reqBits    = (HEADER_BYTES + payloadLen) * 8;
    const percent    = Math.min(100, (reqBits / maxBits) * 100);

    document.getElementById('encode-stats').style.display = 'flex';
    document.getElementById('stat-req-bits').textContent  = reqBits.toLocaleString('tr-TR') + ' bit';
    document.getElementById('stat-max-bits').textContent  = maxBits.toLocaleString('tr-TR') + ' bit';
    document.getElementById('stat-percent').textContent   = percent.toFixed(2) + '%';

    const bar = document.getElementById('capacity-bar-fill');
    bar.style.width      = percent + '%';
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
   Encoding (async — AES-GCM + spread embedding)
   ========================================================================== */

async function handleEncode() {
    if (!originalImage || !originalImageData) {
        showToast('error', 'Görsel Eksik', 'Lütfen önce bir taşıyıcı görsel yükleyin.'); return;
    }
    const message  = document.getElementById('msg-encode').value;
    const passcode = document.getElementById('pass-encode').value;
    const channel  = document.getElementById('channel-encode').value;
    const depth    = parseInt(document.getElementById('depth-encode').value) || 1;

    if (!message.trim()) {
        showToast('warning', 'Mesaj Eksik', 'Lütfen gizlemek istediğiniz mesajı girin.'); return;
    }

    const btn = document.getElementById('btn-encode-action');
    setButtonLoading(btn, true, 'Gizleniyor...');
    await new Promise(r => setTimeout(r, 30)); // spinner paint

    try {
        const packet    = await packPayload(message, passcode, channel, depth);
        const bitStream = bytesToBits(packet);
        const { width, height } = originalImage;

        const canvasStego = document.getElementById('canvas-stego-encode');
        canvasStego.width = width; canvasStego.height = height;
        const ctxStego = canvasStego.getContext('2d');

        const imgData = ctxStego.createImageData(width, height);
        imgData.data.set(originalImageData.data);
        writeBitsToPixels(imgData.data, bitStream, channel, depth);
        ctxStego.putImageData(imgData, 0, 0);

        document.getElementById('placeholder-stego-encode').style.display = 'none';
        document.getElementById('btn-download-stego').style.display = 'flex';
        document.getElementById('btn-compare').style.display = 'flex';

        renderDiffMap(originalImageData.data, imgData.data, width, height);
        renderComparisonHistogram(originalImageData, imgData);

        const encLabel   = (passcode && passcode.trim()) ? 'AES-256-GCM şifreli' : 'şifresiz';
        const depthLabel = depth > 1 ? `, LSB-${depth}` : '';
        showToast('success', 'Gizleme Tamamlandı!',
            `${message.length} karakter, ${CHANNEL_NAMES[channel]} kanalına dağıtık + ${encLabel}${depthLabel} olarak yazıldı.`);
    } catch (e) {
        showToast('error', 'Hata Oluştu', e.message);
    } finally {
        setButtonLoading(btn, false);
        updateCapacityStats();
    }
}

function renderDiffMap(origData, stegoData, width, height) {
    const section = document.getElementById('diff-section');
    const canvas  = document.getElementById('canvas-diff-encode');
    const ctx     = canvas.getContext('2d');

    let changedPixels = 0, changedBits = 0;

    const offscreen = document.createElement('canvas');
    offscreen.width = width; offscreen.height = height;
    const octx = offscreen.getContext('2d');
    const diff  = octx.createImageData(width, height);

    for (let i = 0; i < origData.length; i += 4) {
        const dR = Math.abs(stegoData[i]   - origData[i]);
        const dG = Math.abs(stegoData[i+1] - origData[i+1]);
        const dB = Math.abs(stegoData[i+2] - origData[i+2]);
        // ×255 amplify so single-LSB changes become fully visible
        diff.data[i]   = dR ? 255 : 0;
        diff.data[i+1] = dG ? 255 : 0;
        diff.data[i+2] = dB ? 255 : 0;
        diff.data[i+3] = 255;
        if (dR || dG || dB) { changedPixels++; changedBits += (dR?1:0)+(dG?1:0)+(dB?1:0); }
    }
    octx.putImageData(diff, 0, 0);

    // Dağıtık gömmede değişiklikler tüm görsele yayılır → tam kareyi göster.
    const displayW = Math.min(600, width);
    const scale    = displayW / width;
    const displayH = Math.min(320, Math.round(height * scale));

    canvas.width = displayW; canvas.height = displayH;
    ctx.imageSmoothingEnabled = false;
    ctx.drawImage(offscreen, 0, 0, width, height, 0, 0, displayW, displayH);
    ctx.strokeStyle = 'rgba(0,229,255,0.5)'; ctx.lineWidth = 2;
    ctx.strokeRect(1, 1, displayW - 2, displayH - 2);

    section.style.display = 'block';
    const totalPixels = width * height;
    const coveragePct = (changedPixels / totalPixels * 100).toFixed(2);

    document.getElementById('diff-stats').innerHTML = `
        <div class="diff-stat"><span>Değiştirilen Piksel</span><strong>${changedPixels.toLocaleString('tr-TR')}</strong></div>
        <div class="diff-stat"><span>Toplam Piksel</span><strong>${totalPixels.toLocaleString('tr-TR')}</strong></div>
        <div class="diff-stat"><span>Kaplama Oranı</span><strong>${coveragePct}%</strong></div>
        <div class="diff-stat"><span>Yazılan Bit</span><strong>${changedBits.toLocaleString('tr-TR')}</strong></div>
    `;
    document.querySelector('.diff-desc').textContent =
        'Değişen pikseller ×255 büyütülmüştür. Dağıtık (PRNG) gömme sayesinde noktalar tek bir blokta değil, tüm görsele homojen yayılır. Kırmızı=R, Yeşil=G, Mavi=B.';
}

function downloadStegoImage() {
    const canvas = document.getElementById('canvas-stego-encode');
    if (!canvas) return;
    const baseName = originalFileName ? originalFileName.replace(/\.[^/.]+$/, '') : 'gorsel';
    const link = document.createElement('a');
    link.download = baseName + '_stego.png';
    link.href = canvas.toDataURL('image/png');
    link.click();
    showToast('success', 'İndirme Başlatıldı', `${link.download} olarak kaydedildi.`);
}

/* ==========================================================================
   Comparison Slider (Encode Tab)
   ========================================================================== */

let comparisonSliderValue = 50;

function toggleComparison() {
    const section = document.getElementById('comparison-section');
    if (section.style.display !== 'none') { section.style.display = 'none'; return; }
    if (!originalImageData) return;
    section.style.display = 'block';
    updateComparisonSlider(comparisonSliderValue);
}

function updateComparisonSlider(val) {
    comparisonSliderValue = parseInt(val);
    const canvas = document.getElementById('canvas-comparison');
    const origC  = document.getElementById('canvas-original-encode');
    const stegoC = document.getElementById('canvas-stego-encode');
    if (!origC || !stegoC || !originalImage) return;

    const { width, height } = originalImage;
    canvas.width = width; canvas.height = height;
    const ctx = canvas.getContext('2d');
    const splitX = Math.floor(width * comparisonSliderValue / 100);

    ctx.drawImage(origC,  0, 0, splitX,          height, 0,      0, splitX,          height);
    ctx.drawImage(stegoC, splitX, 0, width - splitX, height, splitX, 0, width - splitX, height);

    ctx.strokeStyle = 'rgba(0,229,255,0.9)'; ctx.lineWidth = 3;
    ctx.beginPath(); ctx.moveTo(splitX, 0); ctx.lineTo(splitX, height); ctx.stroke();

    ctx.fillStyle = 'rgba(0,10,20,0.7)';
    ctx.fillRect(4, 4, 76, 22); ctx.fillRect(splitX + 4, 4, 52, 22);
    ctx.fillStyle = 'rgba(0,229,255,0.9)'; ctx.font = 'bold 11px Outfit';
    ctx.fillText('ORİJİNAL', 8, 18);
    ctx.fillText('STEGO', splitX + 8, 18);
}

/* ==========================================================================
   Comparison Histogram (Encode Tab)
   ========================================================================== */

function renderComparisonHistogram(origImgData, stegoImgData) {
    const section = document.getElementById('histogram-compare-section');
    const canvas  = document.getElementById('canvas-histogram-compare');
    if (!canvas) return;

    canvas.width  = canvas.clientWidth  * window.devicePixelRatio || 600;
    canvas.height = canvas.clientHeight * window.devicePixelRatio || 180;
    const ctx = canvas.getContext('2d');
    const W = canvas.width, H = canvas.height;

    ctx.fillStyle = '#0a0e17'; ctx.fillRect(0, 0, W, H);
    ctx.strokeStyle = 'rgba(255,255,255,0.05)'; ctx.lineWidth = 1;
    for (let i = 1; i < 5; i++) { ctx.beginPath(); ctx.moveTo(W/5*i,0); ctx.lineTo(W/5*i,H); ctx.stroke(); }
    for (let i = 1; i < 4; i++) { ctx.beginPath(); ctx.moveTo(0,H/4*i); ctx.lineTo(W,H/4*i); ctx.stroke(); }

    const buildHist = data => {
        const rH = new Array(256).fill(0), gH = new Array(256).fill(0), bH = new Array(256).fill(0);
        for (let i = 0; i < data.length; i += 4) { rH[data[i]]++; gH[data[i+1]]++; bH[data[i+2]]++; }
        return { rH, gH, bH };
    };

    const orig  = buildHist(origImgData.data);
    const stego = buildHist(stegoImgData.data);
    const maxV  = Math.max(...orig.rH, ...orig.gH, ...orig.bH, ...stego.rH, ...stego.gH, ...stego.bH);
    if (maxV === 0) return;

    drawChannelCurve(ctx, orig.rH,  maxV, W, H, 'rgba(255,23,68,0.15)',  'rgba(255,23,68,0.4)');
    drawChannelCurve(ctx, orig.gH,  maxV, W, H, 'rgba(0,230,118,0.15)',  'rgba(0,230,118,0.4)');
    drawChannelCurve(ctx, orig.bH,  maxV, W, H, 'rgba(0,229,255,0.15)',  'rgba(0,229,255,0.4)');
    drawChannelCurve(ctx, stego.rH, maxV, W, H, 'rgba(255,23,68,0.35)',  'rgba(255,23,68,1)');
    drawChannelCurve(ctx, stego.gH, maxV, W, H, 'rgba(0,230,118,0.35)',  'rgba(0,230,118,1)');
    drawChannelCurve(ctx, stego.bH, maxV, W, H, 'rgba(0,229,255,0.35)',  'rgba(0,229,255,1)');

    ctx.font = '10px Outfit'; ctx.textAlign = 'right';
    ctx.fillStyle = 'rgba(255,255,255,0.4)'; ctx.fillText('Soluk: Orijinal  |  Parlak: Stego', W - 8, H - 6);
    ctx.textAlign = 'left';
    section.style.display = 'block';
}

/* ==========================================================================
   Decoding (async) — auto-detects channel/depth, AES-GCM + integrity check
   ========================================================================== */

async function handleDecode() {
    if (!stegoImage || !stegoImageData) {
        showToast('error', 'Görsel Eksik', 'Lütfen önce çözümlenecek stego görseli yükleyin.'); return;
    }
    const passcode = document.getElementById('pass-decode').value;
    const pixels   = stegoImageData.data;
    const btn      = document.getElementById('btn-decode-action');
    setButtonLoading(btn, true, 'Çözülüyor...');
    await new Promise(r => setTimeout(r, 30));

    try {
        let detectedChannel = null, detectedDepth = null, headerBytes = null;

        outer:
        for (const ch of ['rgb', 'r', 'g', 'b']) {
            for (const dep of [1, 2, 3]) {
                const bits = readBitsFromPixels(pixels, HEADER_BITS, ch, dep);
                if (!bits) continue;
                const bytes = bitsToBytes(bits);
                if (bytes[0] === MAGIC_BYTES[0] && bytes[1] === MAGIC_BYTES[1] && bytes[2] === MAGIC_BYTES[2]) {
                    detectedChannel = ch; detectedDepth = dep; headerBytes = bytes; break outer;
                }
            }
        }

        if (!detectedChannel) {
            showToast('error', 'Geçersiz Görsel', 'Bu görselde StegoShield protokolü ile gizlenmiş veri bulunamadı. Yalnızca StegoShield ile oluşturulan kayıpsız PNG dosyaları desteklenir.');
            document.getElementById('msg-decode').value = 'ÇÖZME HATASI: Geçerli StegoShield imzası bulunamadı.';
            return;
        }

        const flags       = headerBytes[3];
        const encryptFlag = flags & 1;
        const salt        = headerBytes.slice(4, 20);
        const iv          = headerBytes.slice(20, 32);
        const checksum    = headerBytes.slice(32, 36);
        const dataLength  = (headerBytes[36] << 24) | (headerBytes[37] << 16) | (headerBytes[38] << 8) | headerBytes[39];

        if (dataLength <= 0 || dataLength > pixels.length) {
            showToast('error', 'Bozuk Paket', 'Geçersiz paket boyutu.'); return;
        }

        if (encryptFlag && (!passcode || !passcode.trim())) {
            showToast('warning', 'Parola Gerekli', 'Bu mesaj AES-256-GCM ile şifrelenmiştir. Parolayı girip tekrar deneyin.');
            document.getElementById('msg-decode').value = '[ŞİFRELENMİŞ VERİ]: Doğru parolayı girip tekrar deneyin.';
            return;
        }

        const fullBits  = readBitsFromPixels(pixels, HEADER_BITS + dataLength * 8, detectedChannel, detectedDepth);
        const fullBytes = bitsToBytes(fullBits);
        const payload   = fullBytes.slice(HEADER_BYTES);

        let plain;
        if (encryptFlag) {
            try {
                const key = await deriveKey(passcode, salt);
                const pt  = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, payload);
                plain = new Uint8Array(pt);
            } catch (_) {
                showToast('error', 'Parola Hatalı', 'AES-GCM doğrulaması başarısız. Parola yanlış veya veri bozulmuş.');
                document.getElementById('msg-decode').value = 'ÇÖZME HATASI: Parola yanlış veya veri bütünlüğü bozulmuş (GCM tag uyuşmadı).';
                return;
            }
        } else {
            plain = payload;
        }

        // Bütünlük kontrolü (SHA-256 checksum)
        const calc = (await sha256(plain)).slice(0, 4);
        if (!bytesEqual(calc, checksum, 4)) {
            showToast('error', 'Bütünlük Hatası', 'Checksum uyuşmadı — veri bozulmuş olabilir.');
            document.getElementById('msg-decode').value = 'ÇÖZME HATASI: Bütünlük doğrulaması (checksum) başarısız.';
            return;
        }

        const decodedMessage = new TextDecoder().decode(plain);
        document.getElementById('msg-decode').value = decodedMessage;
        document.getElementById('btn-copy-msg').style.display = 'block';

        const meta = document.getElementById('decode-meta');
        meta.style.display = 'flex';
        document.getElementById('meta-channel').textContent = CHANNEL_NAMES[detectedChannel];
        document.getElementById('meta-encrypt').textContent = encryptFlag ? 'AES-256-GCM' : 'Şifresiz';
        document.getElementById('meta-length').textContent  = `${dataLength.toLocaleString('tr-TR')} bayt`;
        document.getElementById('meta-depth').textContent   = DEPTH_NAMES[detectedDepth];

        showToast('success', 'Çözme Başarılı!',
            `Mesaj çözüldü ve bütünlüğü doğrulandı. Kanal: ${CHANNEL_NAMES[detectedChannel]} | ${DEPTH_NAMES[detectedDepth]}${encryptFlag ? ' | AES-256-GCM' : ''}.`);
    } catch (e) {
        showToast('error', 'Çözme Hatası', 'Mesaj çözülemedi. Görsel kayıplı sıkıştırmayla kaydedilmiş olabilir.');
        document.getElementById('msg-decode').value = 'ÇÖZME HATASI: ' + e.message;
    } finally {
        setButtonLoading(btn, false);
    }
}

async function copyDecodedMessage() {
    const text = document.getElementById('msg-decode').value;
    if (!text) return;
    try { await navigator.clipboard.writeText(text); }
    catch (_) { document.getElementById('msg-decode').select(); document.execCommand('copy'); }
    showToast('success', 'Panoya Kopyalandı', 'Gizli mesaj başarıyla panoya kopyalandı.');
}

/* ==========================================================================
   Signature Detection — StegoShield Protocol (spread-aware, all combos)
   ========================================================================== */

let signatureDetected = false;

function runSignatureDetection() {
    const el = document.getElementById('signature-result');
    if (!el || !analyzedImageData) return;
    const pixels = analyzedImageData.data;
    signatureDetected = false;

    for (const ch of ['rgb', 'r', 'g', 'b']) {
        for (const dep of [1, 2, 3]) {
            const bits = readBitsFromPixels(pixels, HEADER_BITS, ch, dep);
            if (!bits) continue;
            const bytes = bitsToBytes(bits);
            if (bytes[0] === MAGIC_BYTES[0] && bytes[1] === MAGIC_BYTES[1] && bytes[2] === MAGIC_BYTES[2]) {
                const encryptFlag = bytes[3] & 1;
                const dataLength  = (bytes[36] << 24) | (bytes[37] << 16) | (bytes[38] << 8) | bytes[39];
                signatureDetected = true;
                el.className = 'signature-box sig-detected';
                el.innerHTML = `
                    <span class="sig-icon">⚠</span>
                    <div class="sig-body">
                        <strong>StegoShield İmzası Tespit Edildi!</strong>
                        <span>Kanal: ${CHANNEL_NAMES[ch]} &nbsp;|&nbsp; ${DEPTH_NAMES[dep]} &nbsp;|&nbsp; ${encryptFlag ? 'AES-256-GCM' : 'Şifresiz'} &nbsp;|&nbsp; Payload: ${dataLength.toLocaleString('tr-TR')} bayt</span>
                    </div>`;
                updateGaugeFromSignature(true);
                verdictState.sig = true; updateFinalVerdict();
                return;
            }
        }
    }

    signatureDetected = false;
    verdictState.sig = false; updateFinalVerdict();
    el.className = 'signature-box sig-clean';
    el.innerHTML = `
        <span class="sig-icon">✓</span>
        <div class="sig-body">
            <strong>StegoShield İmzası Bulunamadı</strong>
            <span>Bu görsel StegoShield protokolüyle oluşturulmamış veya farklı bir araç kullanılmış.</span>
        </div>`;
    updateGaugeFromSignature(false);
}

function updateGaugeFromSignature(detected) {
    if (!detected) return;
    document.getElementById('gauge-percentage').textContent = '100%';
    document.getElementById('gauge-fill-val').style.strokeDashoffset = '0';
    document.getElementById('gauge-fill-val').style.stroke = 'var(--danger)';
    document.getElementById('gauge-percentage').style.color = 'var(--danger)';
    const card = document.getElementById('analysis-status-card');
    card.className = 'analysis-summary-card status-danger';
    document.getElementById('analysis-status-title').textContent = 'Gizli Veri Tespit Edildi!';
    document.getElementById('analysis-status-desc').textContent =
        'StegoShield protokol imzası doğrulandı. Bu görselde gizli veri kesin olarak mevcut.';
}

/* ==========================================================================
   Combined Final Verdict — fuses signature + chi-square + RS + ML
   ========================================================================== */

function setVerdictChip(id, text, hit) {
    const el = document.getElementById(id);
    if (!el) return;
    el.querySelector('strong').textContent = text;
    el.className = 'fv-method' + (hit === true ? ' fv-hit' : hit === false ? ' fv-ok' : '');
}

function updateFinalVerdict() {
    const el = document.getElementById('final-verdict');
    if (!el) return;
    el.style.display = 'block';
    const s = verdictState;

    const chiHigh = s.chi !== null && s.chi >= 0.75;
    const rsHigh  = s.rs  !== null && s.rs  > 25;
    const mlHigh  = s.ml  !== null && s.ml  >= 50;

    setVerdictChip('fv-sig', s.sig === null ? '—' : (s.sig ? 'STEGO' : 'temiz'), s.sig);
    setVerdictChip('fv-chi', s.chi === null ? '—' : `%${Math.round(s.chi * 100)}`, s.chi === null ? null : chiHigh);
    setVerdictChip('fv-rs',  s.rs  === null ? '—' : `%${s.rs.toFixed(0)}`,         s.rs  === null ? null : rsHigh);
    setVerdictChip('fv-ml',  s.ml  === null ? '…' : `%${s.ml.toFixed(0)}`,         s.ml  === null ? null : mlHigh);

    let level, title, desc, icon;
    if (s.sig) {
        level = 'danger'; icon = '⚠'; title = 'Gizli Veri Tespit Edildi — Kesin';
        desc = 'StegoShield protokol imzası doğrulandı. Mesaj boyutundan bağımsız %100 kesin tespit.';
    } else if (mlHigh || chiHigh || rsHigh) {
        level = 'warn'; icon = '⚠'; title = 'Muhtemel Steganografi';
        const hits = [];
        if (mlHigh) hits.push('ML'); if (chiHigh) hits.push('Chi-Square'); if (rsHigh) hits.push('RS');
        desc = `İstatistiksel/ML yöntemler iz buldu (${hits.join(', ')}). Yüksek olasılıkla veri gizlenmiş.`;
    } else if (s.sig === false && (s.ml !== null || s.chi !== null)) {
        level = 'clean'; icon = '✓'; title = 'Görsel Temiz Görünüyor';
        desc = 'İmza bulunamadı, istatistiksel ve ML yöntemler anlamlı iz tespit etmedi. (Çok küçük dağıtık mesajlar yine de gizli olabilir.)';
    } else {
        level = 'idle'; icon = '◎'; title = 'Nihai Karar'; desc = 'Yöntemler değerlendiriliyor…';
    }
    el.className = `final-verdict fv-${level}`;
    document.getElementById('fv-icon').textContent  = icon;
    document.getElementById('fv-title').textContent = title;
    document.getElementById('fv-desc').textContent  = desc;
}

/* ==========================================================================
   ML Prediction — Python backend (RandomForest, gerçek görsellerle eğitilmiş)
   ========================================================================== */

async function runMLPrediction() {
    const section = document.getElementById('ml-section');
    const statusEl = document.getElementById('ml-status');
    const resultEl = document.getElementById('ml-result');
    if (!section) return;
    section.style.display = 'block';
    statusEl.style.display = 'block';
    statusEl.textContent = 'Sunucudaki model çalışıyor…';
    resultEl.style.display = 'none';

    if (!analyzedFile) { statusEl.textContent = 'Görsel dosyası bulunamadı.'; return; }

    try {
        const form = new FormData();
        form.append('image', analyzedFile);
        const res = await fetch(`${ML_BACKEND}/predict`, { method: 'POST', body: form });
        if (!res.ok) throw new Error('HTTP ' + res.status);
        const data = await res.json();

        const pct = data.stego_probability;
        const isStego = data.label === 'stego';
        verdictState.ml = pct; updateFinalVerdict();
        statusEl.style.display = 'none';
        resultEl.style.display = 'block';
        resultEl.className = `ml-result ${isStego ? 'ml-stego' : 'ml-clean'}`;

        const feats = data.features;
        const featRows = Object.entries(feats).map(([k, v]) =>
            `<div class="ml-feat"><span>${k}</span><strong>${v}</strong></div>`).join('');

        resultEl.innerHTML = `
            <div class="ml-verdict">
                <span class="ml-badge">${isStego ? '⚠ STEGO' : '✓ TEMİZ'}</span>
                <span class="ml-prob">Stego olasılığı: <strong>%${pct}</strong></span>
            </div>
            <div class="ml-bar"><div class="ml-bar-fill" style="width:${pct}%"></div></div>
            <div class="ml-feats">${featRows}</div>
            <div class="ml-meta">Model: Random Forest &nbsp;|&nbsp; Eğitim doğruluğu: %${data.model_accuracy} &nbsp;|&nbsp; Sunucu tahmini</div>`;
    } catch (e) {
        statusEl.style.display = 'block';
        resultEl.style.display = 'none';
        statusEl.innerHTML = `⚠ ML sunucusuna ulaşılamadı. Backend'i başlatın:<br><code>cd backend &amp;&amp; python app.py</code>`;
        verdictState.ml = null; updateFinalVerdict();
    }
}

/* ==========================================================================
   Steganalysis (light) — global Chi-Square + visual LSB map / heatmap
   ========================================================================== */

function runAnalysis() {
    if (!analyzedImage || !analyzedImageData) return;

    const channelSelect = document.getElementById('analysis-channel').value;
    const blendFactor   = parseInt(document.getElementById('analysis-contrast').value) / 10;
    const viewMode      = document.getElementById('lsb-view-mode').value;
    const { width, height } = analyzedImage;

    const canvasLsb = document.getElementById('canvas-analysis-lsb');
    canvasLsb.width = width; canvasLsb.height = height;
    const ctxLsb = canvasLsb.getContext('2d');
    const src = analyzedImageData.data;

    if (viewMode === 'heatmap') {
        renderLSBHeatMap(src, width, height, channelSelect, ctxLsb, blendFactor);
    } else {
        const lsbImgData = ctxLsb.createImageData(width, height);
        const dest = lsbImgData.data;
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
    }

    // Global chi-square
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
    if (chi2 === 0) stegoProb = 0;

    const p1 = lsbOnes / total, p0 = 1 - p1;
    const entropy = (p0 > 0 && p1 > 0) ? -(p0 * Math.log2(p0) + p1 * Math.log2(p1)) : 0;

    if (!signatureDetected) {
        const pct = Math.round(stegoProb * 100);
        document.getElementById('gauge-percentage').textContent = `${pct}%`;
        document.getElementById('gauge-fill-val').style.strokeDashoffset = 251.2 * (1 - pct / 100);

        let color, title, desc, cls;
        if (pct < 30) {
            color = 'var(--success)'; title = 'Görsel Temiz'; cls = 'status-clean';
            desc = 'İstatistiksel analizde herhangi bir LSB sapması tespit edilmedi. Görsel doğal görünüyor.';
        } else if (pct < 75) {
            color = 'var(--warning)'; title = 'Şüpheli Dağılım'; cls = 'status-warn';
            desc = 'Piksel bit dağılımında hafif anormallikler tespit edildi.';
        } else {
            color = 'var(--danger)'; title = 'Gizli Veri Tespit Edildi!'; cls = 'status-danger';
            desc = 'DİKKAT: LSB frekans anormalliği yüksek! Steganografi uygulanmış olabilir.';
        }
        document.getElementById('gauge-fill-val').style.stroke = color;
        document.getElementById('gauge-percentage').style.color = color;
        const card = document.getElementById('analysis-status-card');
        card.className = `analysis-summary-card ${cls}`;
        document.getElementById('analysis-status-title').textContent = title;
        document.getElementById('analysis-status-desc').textContent  = desc;
    }

    document.getElementById('metric-pvalue').textContent   = (1 - stegoProb).toFixed(6);
    document.getElementById('metric-entropy').textContent  = entropy.toFixed(4);
    document.getElementById('metric-lsb-mean').textContent = p1.toFixed(4);

    verdictState.chi = stegoProb; updateFinalVerdict();
}

/* LSB Heat Map — local density via integral image (thermal color scale) */
function renderLSBHeatMap(src, width, height, channel, ctx, blendFactor) {
    const n   = width * height;
    const lsb = new Float32Array(n);

    for (let i = 0; i < src.length; i += 4) {
        const pi = i / 4;
        if (channel === 'rgb') lsb[pi] = ((src[i] & 1) + (src[i+1] & 1) + (src[i+2] & 1)) / 3;
        else { const o = channel === 'r' ? 0 : channel === 'g' ? 1 : 2; lsb[pi] = src[i + o] & 1; }
    }

    const W1  = width + 1;
    const sat = new Float32Array((height + 1) * W1);
    for (let y = 1; y <= height; y++)
        for (let x = 1; x <= width; x++)
            sat[y * W1 + x] = lsb[(y-1) * width + (x-1)]
                + sat[(y-1) * W1 + x] + sat[y * W1 + (x-1)] - sat[(y-1) * W1 + (x-1)];

    const r       = 6;
    const imgData = ctx.createImageData(width, height);
    for (let y = 0; y < height; y++) {
        for (let x = 0; x < width; x++) {
            const x1 = Math.max(0, x-r), y1 = Math.max(0, y-r);
            const x2 = Math.min(width, x+r+1), y2 = Math.min(height, y+r+1);
            const area    = (x2-x1)*(y2-y1);
            const sum     = sat[y2*W1+x2] - sat[y1*W1+x2] - sat[y2*W1+x1] + sat[y1*W1+x1];
            const t       = sum / area;
            const idx = (y * width + x) * 4;
            let hR, hG, hB;
            if (t < 0.25)      { const s=t*4;        hR=0;                hG=Math.round(s*180);     hB=200; }
            else if (t < 0.5)  { const s=(t-0.25)*4; hR=0;                hG=Math.round(180+s*75);  hB=Math.round(200*(1-s)); }
            else if (t < 0.75) { const s=(t-0.5)*4;  hR=Math.round(s*255); hG=255;                  hB=0; }
            else               { const s=(t-0.75)*4; hR=255;              hG=Math.round(255*(1-s)); hB=0; }

            const origR = src[idx], origG = src[idx+1], origB = src[idx+2];
            imgData.data[idx]   = Math.round(hR * blendFactor + origR * (1-blendFactor));
            imgData.data[idx+1] = Math.round(hG * blendFactor + origG * (1-blendFactor));
            imgData.data[idx+2] = Math.round(hB * blendFactor + origB * (1-blendFactor));
            imgData.data[idx+3] = src[idx+3];
        }
    }
    ctx.putImageData(imgData, 0, 0);
}

function normalCDF(z) {
    const t = 1 / (1 + 0.2316419 * Math.abs(z));
    const d = 0.3989423 * Math.exp(-z * z / 2);
    const p = d * t * (0.3193815 + t * (-0.3565638 + t * (1.781478 + t * (-1.821256 + t * 1.330274))));
    return z > 0 ? 1 - p : p;
}

/* ==========================================================================
   Heavy Steganalysis — RS (Fridrich) + Block Chi-Square via Web Worker
   ========================================================================== */

let analysisWorker = null;

function getWorker() {
    if (analysisWorker === null) {
        try { analysisWorker = new Worker('analysis.worker.js'); }
        catch (_) { analysisWorker = false; } // workers unsupported → main-thread fallback
    }
    return analysisWorker;
}

function runHeavyAnalysis() {
    if (!analyzedImage || !analyzedImageData) return;
    const { width, height } = analyzedImage;

    document.getElementById('rs-section').style.display = 'block';
    document.getElementById('rs-verdict').textContent = 'Hesaplanıyor…';
    document.getElementById('rs-verdict').style.color = 'var(--text-muted, #9aa7c0)';

    const worker = getWorker();
    if (worker) {
        const copy = new Uint8ClampedArray(analyzedImageData.data);
        worker.onmessage = (e) => {
            const { rs, block } = e.data;
            updateRSDisplay(rs);
            drawBlockChiSquare(block, width, height);
        };
        worker.onerror = () => { // fallback if worker errors at runtime
            updateRSDisplay(computeRS(analyzedImageData.data, width, height));
            drawBlockChiSquare(computeBlockChi(analyzedImageData.data, width, height), width, height);
        };
        worker.postMessage({ type: 'analyze', data: copy, width, height }, [copy.buffer]);
    } else {
        // Synchronous fallback
        setTimeout(() => {
            updateRSDisplay(computeRS(analyzedImageData.data, width, height));
            drawBlockChiSquare(computeBlockChi(analyzedImageData.data, width, height), width, height);
        }, 20);
    }
}

function updateRSDisplay(rs) {
    const { r1, s1, rm1, sm1, estimatedRate } = rs;
    document.getElementById('rs-r1').textContent   = (r1  * 100).toFixed(2) + '%';
    document.getElementById('rs-s1').textContent   = (s1  * 100).toFixed(2) + '%';
    document.getElementById('rs-rm1').textContent  = (rm1 * 100).toFixed(2) + '%';
    document.getElementById('rs-sm1').textContent  = (sm1 * 100).toFixed(2) + '%';
    document.getElementById('rs-rate').textContent = estimatedRate.toFixed(1) + '%';
    verdictState.rs = estimatedRate; updateFinalVerdict();

    const verdictEl = document.getElementById('rs-verdict');
    if (signatureDetected && estimatedRate <= 25) {
        verdictEl.textContent = 'İmza ile doğrulandı (dağıtık/düşük kaplama — istatistiksel iz zayıf)';
        verdictEl.style.color = 'var(--danger)';
    } else if (estimatedRate > 25) {
        verdictEl.textContent = 'Steganografi İzleri Tespit Edildi'; verdictEl.style.color = 'var(--danger)';
    } else if (estimatedRate > 12) {
        verdictEl.textContent = 'Şüpheli Asimetri'; verdictEl.style.color = 'var(--warning)';
    } else {
        verdictEl.textContent = 'Doğal Görünüyor (Temiz)'; verdictEl.style.color = 'var(--success)';
    }
}

/* Block Chi-Square heat map — paints per-block stego probability */
function drawBlockChiSquare(block, width, height) {
    const section = document.getElementById('blockchi-section');
    const canvas  = document.getElementById('canvas-blockchi');
    if (!section || !canvas) return;
    const { bw, bh, probs, maxProb, blockSize } = block;

    const displayW = Math.min(600, width);
    const scale    = displayW / width;
    const displayH = Math.min(360, Math.round(height * scale));
    canvas.width = displayW; canvas.height = displayH;
    const ctx = canvas.getContext('2d');

    const cellW = displayW / bw, cellH = displayH / bh;
    for (let by = 0; by < bh; by++) {
        for (let bx = 0; bx < bw; bx++) {
            const p = probs[by * bw + bx]; // 0..1
            let cR, cG, cB;
            if (p < 0.5) { const s = p * 2; cR = Math.round(s*255); cG = Math.round(120+s*135); cB = 40; }
            else         { const s = (p-0.5)*2; cR = 255; cG = Math.round(255*(1-s)); cB = 0; }
            ctx.fillStyle = `rgba(${cR},${cG},${cB},0.85)`;
            ctx.fillRect(bx * cellW, by * cellH, Math.ceil(cellW), Math.ceil(cellH));
        }
    }
    ctx.strokeStyle = 'rgba(0,0,0,0.25)'; ctx.lineWidth = 1;
    for (let bx = 1; bx < bw; bx++) { ctx.beginPath(); ctx.moveTo(bx*cellW,0); ctx.lineTo(bx*cellW,displayH); ctx.stroke(); }
    for (let by = 1; by < bh; by++) { ctx.beginPath(); ctx.moveTo(0,by*cellH); ctx.lineTo(displayW,by*cellH); ctx.stroke(); }

    section.style.display = 'block';
    const maxEl = document.getElementById('blockchi-max');
    if (maxEl) maxEl.textContent = (maxProb * 100).toFixed(1) + '%';
    const sizeEl = document.getElementById('blockchi-size');
    if (sizeEl) sizeEl.textContent = `${blockSize}×${blockSize} px`;
}

/* ── Main-thread fallback implementations (mirror the worker) ─────────────── */

function computeRS(src, width, height) {
    let R1 = 0, S1 = 0, Rm1 = 0, Sm1 = 0, total = 0;
    for (const ch of [0, 1, 2]) {
        for (let y = 0; y < height; y++) {
            for (let x = 0; x < width - 1; x++) {
                const idx = (y * width + x) * 4;
                const a = src[idx + ch], b = src[idx + 4 + ch];
                const f0 = Math.abs(b - a);
                const a1 = a ^ 1, f1 = Math.abs(b - a1);
                if (f1 > f0) R1++; else if (f1 < f0) S1++;
                const am1 = (a % 2 === 0) ? Math.max(0, a - 1) : Math.min(255, a + 1);
                const fm1 = Math.abs(b - am1);
                if (fm1 > f0) Rm1++; else if (fm1 < f0) Sm1++;
                total++;
            }
        }
    }
    const r1 = R1/total, s1 = S1/total, rm1 = Rm1/total, sm1 = Sm1/total;
    const diff = r1 - rm1;
    const estimatedRate = Math.min(100, Math.max(0, diff / Math.max(r1, 0.0001) * 200));
    return { r1, s1, rm1, sm1, estimatedRate };
}

function computeBlockChi(src, width, height) {
    const blockSize = 64;
    const bw = Math.max(1, Math.ceil(width / blockSize));
    const bh = Math.max(1, Math.ceil(height / blockSize));
    const probs = new Float32Array(bw * bh);
    let maxProb = 0;

    for (let by = 0; by < bh; by++) {
        for (let bx = 0; bx < bw; bx++) {
            const x0 = bx * blockSize, y0 = by * blockSize;
            const x1 = Math.min(width, x0 + blockSize), y1 = Math.min(height, y0 + blockSize);
            const f = new Float64Array(256);
            for (let y = y0; y < y1; y++)
                for (let x = x0; x < x1; x++) {
                    const idx = (y * width + x) * 4;
                    f[src[idx]]++; f[src[idx+1]]++; f[src[idx+2]]++;
                }
            let chi2 = 0, df = 0;
            for (let k = 0; k < 128; k++) {
                const s = f[2*k] + f[2*k+1];
                if (s > 0) { const d = f[2*k] - f[2*k+1]; chi2 += d*d / s; df++; }
            }
            let prob = 0;
            if (df > 0) {
                const v = 2 / (9 * df);
                const z = (Math.pow(chi2 / df, 1/3) - (1 - v)) / Math.sqrt(v);
                const t = 1 / (1 + 0.2316419 * Math.abs(z));
                const dd = 0.3989423 * Math.exp(-z * z / 2);
                const pp = dd * t * (0.3193815 + t * (-0.3565638 + t * (1.781478 + t * (-1.821256 + t * 1.330274))));
                const cdf = z > 0 ? 1 - pp : pp;
                prob = 1 - cdf;
            }
            probs[by * bw + bx] = prob;
            if (prob > maxProb) maxProb = prob;
        }
    }
    return { bw, bh, probs, maxProb, blockSize };
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

    ctx.fillStyle = '#0a0e17'; ctx.fillRect(0, 0, W, H);
    ctx.strokeStyle = 'rgba(255,255,255,0.05)'; ctx.lineWidth = 1;
    for (let i = 1; i < 5; i++) { ctx.beginPath(); ctx.moveTo(W/5*i,0); ctx.lineTo(W/5*i,H); ctx.stroke(); }
    for (let i = 1; i < 4; i++) { ctx.beginPath(); ctx.moveTo(0,H/4*i); ctx.lineTo(W,H/4*i); ctx.stroke(); }

    const rH = new Array(256).fill(0), gH = new Array(256).fill(0), bH = new Array(256).fill(0);
    const px = imgData.data;
    for (let i = 0; i < px.length; i += 4) { rH[px[i]]++; gH[px[i+1]]++; bH[px[i+2]]++; }
    const maxVal = Math.max(...rH, ...gH, ...bH);
    if (maxVal === 0) return;

    drawChannelCurve(ctx, rH, maxVal, W, H, 'rgba(255,23,68,0.4)',  'rgba(255,23,68,1)');
    drawChannelCurve(ctx, gH, maxVal, W, H, 'rgba(0,230,118,0.4)',  'rgba(0,230,118,1)');
    drawChannelCurve(ctx, bH, maxVal, W, H, 'rgba(0,229,255,0.4)',  'rgba(0,229,255,1)');
}

function drawChannelCurve(ctx, hist, maxVal, W, H, fillColor, strokeColor) {
    ctx.beginPath(); ctx.moveTo(0, H);
    const step = W / 256;
    for (let i = 0; i < 256; i++) ctx.lineTo(i * step, H - (hist[i] / maxVal) * (H - 15) - 4);
    ctx.lineTo(W, H); ctx.closePath();
    ctx.fillStyle = fillColor; ctx.fill();
    ctx.strokeStyle = strokeColor; ctx.lineWidth = 1.5; ctx.stroke();
}
