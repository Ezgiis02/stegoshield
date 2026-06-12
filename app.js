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
let originalFileName = '';

// Protocol constants
const MAGIC_BYTES = [83, 84, 71]; // ASCII: "STG"
const CHANNEL_CODES = { rgb: 0, r: 1, g: 2, b: 3 };
const CHANNEL_NAMES = { rgb: 'Tüm Kanallar (RGB)', r: 'Kırmızı (R)', g: 'Yeşil (G)', b: 'Mavi (B)' };
const DEPTH_NAMES   = { 1: 'LSB-1 (Standart)', 2: 'LSB-2 (2× kapasite)', 3: 'LSB-3 (3× kapasite)' };

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
    if (input.type === 'password') { input.type = 'text'; button.textContent = 'Gizle'; }
    else { input.type = 'password'; button.textContent = 'Göster'; }
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
        i = (i + 1) % 256; j = (j + s[i]) % 256;
        x = s[i]; s[i] = s[j]; s[j] = x;
        out[y] = bytes[y] ^ s[(s[i] + s[j]) % 256];
    }
    return out;
}

/* ==========================================================================
   Steganography Protocol
   FLAGS byte: bit0=encrypt, bits2-1=channel, bits4-3=depthCode (depth-1)
   ========================================================================== */

function packPayload(messageText, passcode, channel, depth = 1) {
    const encoder = new TextEncoder();
    let payloadBytes = encoder.encode(messageText);
    const encryptFlag  = (passcode && passcode.trim() !== '') ? 1 : 0;
    if (encryptFlag) payloadBytes = rc4(passcode, payloadBytes);

    const channelCode = CHANNEL_CODES[channel] ?? 0;
    const depthCode   = Math.max(0, depth - 1) & 3;
    const flags = (depthCode << 3) | (channelCode << 1) | encryptFlag;

    const packet = new Uint8Array(3 + 1 + 4 + payloadBytes.length);
    packet[0] = MAGIC_BYTES[0]; packet[1] = MAGIC_BYTES[1]; packet[2] = MAGIC_BYTES[2];
    packet[3] = flags;
    const len = payloadBytes.length;
    packet[4] = (len >>> 24) & 0xFF; packet[5] = (len >>> 16) & 0xFF;
    packet[6] = (len >>> 8) & 0xFF;  packet[7] = len & 0xFF;
    packet.set(payloadBytes, 8);
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

/* Multi-depth bit I/O — depth 1/2/3 LSBs per channel slot */
function writeBitsToPixels(pixels, bitStream, channel, depth) {
    const bLen = bitStream.length;
    const mask = ~((1 << depth) - 1) & 0xFF;
    let bp = 0;
    if (channel === 'rgb') {
        for (let i = 0; i < pixels.length && bp < bLen; i += 4)
            for (let c = 0; c < 3 && bp < bLen; c++) {
                let v = pixels[i + c] & mask;
                for (let d = depth - 1; d >= 0 && bp < bLen; d--) v |= bitStream[bp++] << d;
                pixels[i + c] = v;
            }
    } else {
        const off = channel === 'g' ? 1 : channel === 'b' ? 2 : 0;
        for (let i = 0; i < pixels.length && bp < bLen; i += 4) {
            let v = pixels[i + off] & mask;
            for (let d = depth - 1; d >= 0 && bp < bLen; d--) v |= bitStream[bp++] << d;
            pixels[i + off] = v;
        }
    }
}

function readBitsFromPixels(pixels, bitCount, channel, depth) {
    const bits = new Uint8Array(bitCount);
    let bp = 0;
    if (channel === 'rgb') {
        for (let i = 0; i < pixels.length && bp < bitCount; i += 4)
            for (let c = 0; c < 3 && bp < bitCount; c++)
                for (let d = depth - 1; d >= 0 && bp < bitCount; d--)
                    bits[bp++] = (pixels[i + c] >> d) & 1;
    } else {
        const off = channel === 'g' ? 1 : channel === 'b' ? 2 : 0;
        for (let i = 0; i < pixels.length && bp < bitCount; i += 4)
            for (let d = depth - 1; d >= 0 && bp < bitCount; d--)
                bits[bp++] = (pixels[i + off] >> d) & 1;
    }
    return bits;
}

// Backward-compat wrapper (depth=1)
function readBitsInChannel(pixels, bitCount, channel) {
    return readBitsFromPixels(pixels, bitCount, channel, 1);
}

/* ==========================================================================
   File Drop & Drag Listeners
   ========================================================================== */

function setupDragDrop(zoneId, inputId, infoId, callback) {
    const zone  = document.getElementById(zoneId);
    const input = document.getElementById(inputId);
    zone.addEventListener('click', () => input.click());
    zone.addEventListener('dragover',  e => { e.preventDefault(); zone.classList.add('dragover'); });
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
    document.getElementById(infoId).style.display = 'block';
    document.getElementById(infoId).textContent = `✓  ${file.name}  (${(file.size / 1024).toFixed(1)} KB)`;
    const reader = new FileReader();
    reader.onload = e => { const img = new Image(); img.onload = () => callback(img); img.src = e.target.result; };
    reader.readAsDataURL(file);
}

document.addEventListener('DOMContentLoaded', () => {

    // ── Encode Tab ──────────────────────────────────────────────────────────
    setupDragDrop('drop-encode', 'file-encode', 'info-encode', img => {
        originalImage = img;
        const canvas = document.getElementById('canvas-original-encode');
        const ctx = canvas.getContext('2d');
        canvas.width = img.width; canvas.height = img.height;
        ctx.drawImage(img, 0, 0);
        originalImageData = ctx.getImageData(0, 0, img.width, img.height);

        document.getElementById('placeholder-orig-encode').style.display = 'none';
        ['msg-encode','pass-encode','channel-encode','depth-encode','btn-encode-action'].forEach(id => {
            document.getElementById(id).disabled = false;
        });

        const cs = document.getElementById('canvas-stego-encode');
        cs.getContext('2d').clearRect(0, 0, cs.width, cs.height);
        document.getElementById('placeholder-stego-encode').style.display = 'flex';
        document.getElementById('btn-download-stego').style.display = 'none';
        document.getElementById('btn-compare').style.display = 'none';
        document.getElementById('encode-stats').style.display = 'none';
        document.getElementById('comparison-section').style.display = 'none';
        document.getElementById('histogram-compare-section').style.display = 'none';
        updateCapacityStats();

        showToast('info', 'Görsel Yüklendi', `${img.width}×${img.height} piksel (${(img.width * img.height * 3 / 8 / 1024).toFixed(0)} KB maks. kapasite).`);
    });

    // ── Decode Tab ──────────────────────────────────────────────────────────
    setupDragDrop('drop-decode', 'file-decode', 'info-decode', img => {
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
    setupDragDrop('drop-analyze', 'file-analyze', 'info-analyze', img => {
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
        runRSAnalysis();
        renderHistogram(analyzedImageData);
        showToast('info', 'Analiz Başlatıldı', `${img.width}×${img.height} piksel taranıyor.`);
    });

    // Live capacity updates
    document.getElementById('msg-encode').addEventListener('input', updateCapacityStats);
    document.getElementById('pass-encode').addEventListener('input', updateCapacityStats);
    document.getElementById('channel-encode').addEventListener('change', updateCapacityStats);
    document.getElementById('depth-encode').addEventListener('change', updateCapacityStats);
});

/* ==========================================================================
   Capacity Stats
   ========================================================================== */

function updateCapacityStats() {
    if (!originalImage) return;
    const message    = document.getElementById('msg-encode').value;
    const channel    = document.getElementById('channel-encode').value;
    const depth      = parseInt(document.getElementById('depth-encode').value) || 1;
    const pixelCount = originalImage.width * originalImage.height;
    const maxBits    = pixelCount * (channel === 'rgb' ? 3 : 1) * depth;
    const reqBits    = 64 + new TextEncoder().encode(message).length * 8;
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
   Encoding
   ========================================================================== */

function handleEncode() {
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

    setTimeout(() => {
        try {
            const packet    = packPayload(message, passcode, channel, depth);
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

            const encLabel = (passcode && passcode.trim()) ? 'RC4 şifreli' : 'şifresiz';
            const depthLabel = depth > 1 ? `, LSB-${depth}` : '';
            showToast('success', 'Gizleme Tamamlandı!',
                `${message.length} karakter, ${CHANNEL_NAMES[channel]} kanalına ${encLabel}${depthLabel} olarak yazıldı.`);
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
    const ctx     = canvas.getContext('2d');

    let changedPixels = 0, changedBits = 0, lastChangedIdx = 0;

    const offscreen = document.createElement('canvas');
    offscreen.width = width; offscreen.height = height;
    const octx = offscreen.getContext('2d');
    const diff  = octx.createImageData(width, height);

    for (let i = 0; i < origData.length; i += 4) {
        const dR = Math.abs(stegoData[i]   - origData[i]);
        const dG = Math.abs(stegoData[i+1] - origData[i+1]);
        const dB = Math.abs(stegoData[i+2] - origData[i+2]);
        diff.data[i] = dR * 255; diff.data[i+1] = dG * 255; diff.data[i+2] = dB * 255; diff.data[i+3] = 255;
        if (dR || dG || dB) { changedPixels++; changedBits += (dR?1:0)+(dG?1:0)+(dB?1:0); lastChangedIdx = i; }
    }
    octx.putImageData(diff, 0, 0);

    const lastPixel = lastChangedIdx / 4;
    const lastRow   = Math.floor(lastPixel / width);
    const lastCol   = lastPixel % width;
    const cropH     = Math.min(height, lastRow + 3);
    const cropW     = Math.min(width, lastCol > width * 0.5 ? width : lastCol + 64);
    const displayW  = 600;
    const scale     = displayW / cropW;
    const displayH  = Math.round(cropH * scale);

    canvas.width  = displayW;
    canvas.height = Math.min(displayH, 320);
    ctx.imageSmoothingEnabled = false;
    ctx.drawImage(offscreen, 0, 0, cropW, cropH, 0, 0, displayW, Math.min(displayH, 320));
    ctx.strokeStyle = 'rgba(0,229,255,0.5)'; ctx.lineWidth = 2;
    ctx.strokeRect(1, 1, displayW - 2, Math.min(displayH, 320) - 2);

    section.style.display = 'block';
    const totalPixels  = width * height;
    const coveragePct  = (changedPixels / totalPixels * 100).toFixed(2);
    const zoomLabel    = cropW < width ? ` (sol ${cropW}×${cropH} px gösteriliyor)` : '';

    document.getElementById('diff-stats').innerHTML = `
        <div class="diff-stat"><span>Değiştirilen Piksel</span><strong>${changedPixels.toLocaleString('tr-TR')}</strong></div>
        <div class="diff-stat"><span>Toplam Piksel</span><strong>${totalPixels.toLocaleString('tr-TR')}</strong></div>
        <div class="diff-stat"><span>Kaplama Oranı</span><strong>${coveragePct}%</strong></div>
        <div class="diff-stat"><span>Yazılan Bit</span><strong>${changedBits.toLocaleString('tr-TR')}</strong></div>
    `;
    document.querySelector('.diff-desc').textContent =
        `Mesajın görselde kapladığı alan büyütülerek gösterilir${zoomLabel}. Kırmızı=R, Yeşil=G, Mavi=B kanalı değişti.`;
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
    if (section.style.display !== 'none') {
        section.style.display = 'none';
        return;
    }
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

    // Draw original semi-transparent
    drawChannelCurve(ctx, orig.rH,  maxV, W, H, 'rgba(255,23,68,0.15)',  'rgba(255,23,68,0.4)');
    drawChannelCurve(ctx, orig.gH,  maxV, W, H, 'rgba(0,230,118,0.15)',  'rgba(0,230,118,0.4)');
    drawChannelCurve(ctx, orig.bH,  maxV, W, H, 'rgba(0,229,255,0.15)',  'rgba(0,229,255,0.4)');
    // Draw stego solid
    drawChannelCurve(ctx, stego.rH, maxV, W, H, 'rgba(255,23,68,0.35)',  'rgba(255,23,68,1)');
    drawChannelCurve(ctx, stego.gH, maxV, W, H, 'rgba(0,230,118,0.35)',  'rgba(0,230,118,1)');
    drawChannelCurve(ctx, stego.bH, maxV, W, H, 'rgba(0,229,255,0.35)',  'rgba(0,229,255,1)');

    // Legend
    ctx.font = '10px Outfit'; ctx.textAlign = 'right';
    ctx.fillStyle = 'rgba(255,255,255,0.4)'; ctx.fillText('Soluk: Orijinal  |  Parlak: Stego', W - 8, H - 6);
    ctx.textAlign = 'left';

    section.style.display = 'block';
}

/* ==========================================================================
   Decoding — Auto-detects channel and bit-depth from packet header
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
            let detectedChannel = null, detectedDepth = null, headerBytes = null;

            outer:
            for (const ch of ['rgb', 'r', 'g', 'b']) {
                for (const dep of [1, 2, 3]) {
                    const bytes = bitsToBytes(readBitsFromPixels(pixels, 64, ch, dep));
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
            const dataLength  = (headerBytes[4] << 24) | (headerBytes[5] << 16) | (headerBytes[6] << 8) | headerBytes[7];

            if (dataLength <= 0 || dataLength > pixels.length) {
                showToast('error', 'Bozuk Paket', 'Geçersiz paket boyutu.'); return;
            }

            const fullBytes  = bitsToBytes(readBitsFromPixels(pixels, 64 + dataLength * 8, detectedChannel, detectedDepth));
            let payloadBytes = fullBytes.slice(8);

            if (encryptFlag) {
                if (!passcode || !passcode.trim()) {
                    showToast('warning', 'Parola Gerekli', 'Bu mesaj RC4 ile şifrelenmiştir. Parolayı girip tekrar deneyin.');
                    document.getElementById('msg-decode').value = '[ŞİFRELENMİŞ VERİ]: Doğru parolayı girip tekrar deneyin.';
                    return;
                }
                payloadBytes = rc4(passcode, payloadBytes);
            }

            const decodedMessage = new TextDecoder().decode(payloadBytes);
            document.getElementById('msg-decode').value = decodedMessage;
            document.getElementById('btn-copy-msg').style.display = 'block';

            const meta = document.getElementById('decode-meta');
            meta.style.display = 'flex';
            document.getElementById('meta-channel').textContent = CHANNEL_NAMES[detectedChannel];
            document.getElementById('meta-encrypt').textContent = encryptFlag ? 'RC4 Şifreli' : 'Şifresiz';
            document.getElementById('meta-length').textContent  = `${dataLength.toLocaleString('tr-TR')} bayt`;
            document.getElementById('meta-depth').textContent   = DEPTH_NAMES[detectedDepth];

            showToast('success', 'Çözme Başarılı!',
                `${dataLength} bayt mesaj çözüldü. Kanal: ${CHANNEL_NAMES[detectedChannel]} | ${DEPTH_NAMES[detectedDepth]}${encryptFlag ? ' | RC4 şifreli' : ''}.`);
        } catch (e) {
            showToast('error', 'Çözme Hatası', 'Mesaj çözülemedi. Parola yanlış olabilir veya görsel kayıplı sıkıştırmayla kaydedilmiş olabilir.');
            document.getElementById('msg-decode').value = 'ÇÖZME HATASI: Karakter kodlaması çözülemedi.';
        } finally {
            setButtonLoading(btn, false);
        }
    }, 50);
}

async function copyDecodedMessage() {
    const text = document.getElementById('msg-decode').value;
    if (!text) return;
    try { await navigator.clipboard.writeText(text); }
    catch (_) { document.getElementById('msg-decode').select(); document.execCommand('copy'); }
    showToast('success', 'Panoya Kopyalandı', 'Gizli mesaj başarıyla panoya kopyalandı.');
}

/* ==========================================================================
   Signature Detection — StegoShield Protocol (all channels × all depths)
   ========================================================================== */

let signatureDetected = false;

function runSignatureDetection() {
    const el = document.getElementById('signature-result');
    if (!el || !analyzedImageData) return;
    const pixels = analyzedImageData.data;
    signatureDetected = false;

    for (const ch of ['rgb', 'r', 'g', 'b']) {
        for (const dep of [1, 2, 3]) {
            const bytes = bitsToBytes(readBitsFromPixels(pixels, 64, ch, dep));
            if (bytes[0] === MAGIC_BYTES[0] && bytes[1] === MAGIC_BYTES[1] && bytes[2] === MAGIC_BYTES[2]) {
                const encryptFlag = bytes[3] & 1;
                const dataLength  = (bytes[4] << 24) | (bytes[5] << 16) | (bytes[6] << 8) | bytes[7];
                signatureDetected = true;
                el.className = 'signature-box sig-detected';
                el.innerHTML = `
                    <span class="sig-icon">⚠</span>
                    <div class="sig-body">
                        <strong>StegoShield İmzası Tespit Edildi!</strong>
                        <span>Kanal: ${CHANNEL_NAMES[ch]} &nbsp;|&nbsp; ${DEPTH_NAMES[dep]} &nbsp;|&nbsp; ${encryptFlag ? 'RC4 Şifreli' : 'Şifresiz'} &nbsp;|&nbsp; Payload: ${dataLength.toLocaleString('tr-TR')} bayt</span>
                    </div>`;
                updateGaugeFromSignature(true);
                return;
            }
        }
    }

    signatureDetected = false;
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
   Steganalysis Module — Chi-Square + Visual LSB Map
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

    // Integral image (prefix sum)
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
            const density = sum / area;
            const t = density;
            const idx = (y * width + x) * 4;
            let hR, hG, hB;
            if (t < 0.25)      { const s=t*4;   hR=0;          hG=Math.round(s*180); hB=200; }
            else if (t < 0.5)  { const s=(t-0.25)*4; hR=0;    hG=Math.round(180+s*75); hB=Math.round(200*(1-s)); }
            else if (t < 0.75) { const s=(t-0.5)*4;  hR=Math.round(s*255); hG=255; hB=0; }
            else               { const s=(t-0.75)*4; hR=255;  hG=Math.round(255*(1-s)); hB=0; }

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
   RS Steganalysis — Fridrich et al. Regular/Singular Method
   ========================================================================== */

function runRSAnalysis() {
    if (!analyzedImage || !analyzedImageData) return;
    const src = analyzedImageData.data;
    const { width, height } = analyzedImage;

    let R1 = 0, S1 = 0, Rm1 = 0, Sm1 = 0, total = 0;

    // Process each RGB channel, adjacent horizontal pairs
    for (const ch of [0, 1, 2]) {
        for (let y = 0; y < height; y++) {
            for (let x = 0; x < width - 1; x++) {
                const idx = (y * width + x) * 4;
                const a = src[idx + ch], b = src[(idx + 4) + ch];
                const f0 = Math.abs(b - a);

                // F1: flip LSB of a (XOR 1: even→odd, odd→even)
                const a1  = a ^ 1;
                const f1  = Math.abs(b - a1);
                if (f1 > f0) R1++; else if (f1 < f0) S1++;

                // F-1: negative flip of a (even→a-1, odd→a+1, clamped)
                const am1 = (a % 2 === 0) ? Math.max(0, a - 1) : Math.min(255, a + 1);
                const fm1 = Math.abs(b - am1);
                if (fm1 > f0) Rm1++; else if (fm1 < f0) Sm1++;

                total++;
            }
        }
    }

    const r1 = R1/total, s1 = S1/total, rm1 = Rm1/total, sm1 = Sm1/total;

    // Asymmetry between F1 and F-1 indicates steganography
    // For natural images: r1 ≈ rm1; for stego: r1 > rm1
    const diff = r1 - rm1;
    const estimatedRate = Math.min(100, Math.max(0, diff / Math.max(r1, 0.0001) * 200));

    document.getElementById('rs-r1').textContent   = (r1  * 100).toFixed(2) + '%';
    document.getElementById('rs-s1').textContent   = (s1  * 100).toFixed(2) + '%';
    document.getElementById('rs-rm1').textContent  = (rm1 * 100).toFixed(2) + '%';
    document.getElementById('rs-sm1').textContent  = (sm1 * 100).toFixed(2) + '%';
    document.getElementById('rs-rate').textContent = estimatedRate.toFixed(1) + '%';

    const verdictEl = document.getElementById('rs-verdict');
    if (diff > 0.005) {
        verdictEl.textContent = 'Steganografi İzleri Tespit Edildi'; verdictEl.style.color = 'var(--danger)';
    } else if (diff > 0.001) {
        verdictEl.textContent = 'Hafif Anomali Mevcut'; verdictEl.style.color = 'var(--warning)';
    } else {
        verdictEl.textContent = 'Doğal Görünüyor (Temiz)'; verdictEl.style.color = 'var(--success)';
    }

    document.getElementById('rs-section').style.display = 'block';
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
