/* ==========================================================================
   StegoShield Analysis Worker
   Ağır steganaliz hesaplamaları (RS / Fridrich + blok bazlı chi-square) ana
   iş parçacığını (UI thread) bloklamadan arka planda burada çalışır.
   ========================================================================== */

self.onmessage = function (e) {
    const { type, data, width, height } = e.data;
    if (type !== 'analyze') return;
    const rs    = computeRS(data, width, height);
    const block = computeBlockChi(data, width, height);
    self.postMessage({ type: 'result', rs, block });
};

/* RS Steganalysis — Fridrich et al. Regular/Singular groups */
function computeRS(src, width, height) {
    let R1 = 0, S1 = 0, Rm1 = 0, Sm1 = 0, total = 0;
    for (let ch = 0; ch < 3; ch++) {
        for (let y = 0; y < height; y++) {
            for (let x = 0; x < width - 1; x++) {
                const idx = (y * width + x) * 4;
                const a = src[idx + ch], b = src[idx + 4 + ch];
                const f0 = Math.abs(b - a);

                const a1 = a ^ 1;
                const f1 = Math.abs(b - a1);
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

/* Block Chi-Square — sliding 64×64 windows; per-block stego probability */
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
                prob = 1 - normalCDF(z);
            }
            probs[by * bw + bx] = prob;
            if (prob > maxProb) maxProb = prob;
        }
    }
    return { bw, bh, probs, maxProb, blockSize };
}

function normalCDF(z) {
    const t = 1 / (1 + 0.2316419 * Math.abs(z));
    const d = 0.3989423 * Math.exp(-z * z / 2);
    const p = d * t * (0.3193815 + t * (-0.3565638 + t * (1.781478 + t * (-1.821256 + t * 1.330274))));
    return z > 0 ? 1 - p : p;
}
