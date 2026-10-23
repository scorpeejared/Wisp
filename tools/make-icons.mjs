// Generates the app icons with no third-party dependencies.
//
// Wisp ships no npm packages by design, so the icons are drawn procedurally and
// encoded as PNG here (and wrapped in an ICO for Windows) using only Node's
// built-in zlib.
//
//   node tools/make-icons.mjs

import { deflateSync } from "node:zlib";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const OUT = join(dirname(fileURLToPath(import.meta.url)), "..", "src-tauri", "icons");

const CRC_TABLE = (() => {
  const table = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c;
  }
  return table;
})();

function crc32(buf) {
  let c = -1;
  for (const byte of buf) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

function chunk(type, data) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, "ascii"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([length, body, crc]);
}

function encodePng(size, rgba) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // colour type: RGBA
  // 10-12: deflate / adaptive filtering / no interlace, all zero.

  // One filter byte (0 = None) per scanline, then the raw pixels.
  const raw = Buffer.alloc(size * (size * 4 + 1));
  for (let y = 0; y < size; y++) {
    const rowStart = y * (size * 4 + 1);
    raw[rowStart] = 0;
    rgba.copy(raw, rowStart + 1, y * size * 4, (y + 1) * size * 4);
  }

  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", ihdr),
    chunk("IDAT", deflateSync(raw, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

/// A pale flame on a dark rounded square: a wisp.
function draw(size) {
  const rgba = Buffer.alloc(size * size * 4);
  const s = (v) => v * size;
  const radius = s(0.22);

  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const i = (y * size + x) * 4;

      // Rounded-square background mask.
      const dx = Math.max(radius - x, 0, x - (size - radius));
      const dy = Math.max(radius - y, 0, y - (size - radius));
      const corner = Math.hypot(dx, dy);
      const bgAlpha = clamp(radius - corner + 1, 0, 1) || (dx === 0 && dy === 0 ? 1 : 0);

      // Vertical gradient for the plate.
      const t = y / size;
      let r = lerp(18, 10, t);
      let g = lerp(20, 12, t);
      let b = lerp(30, 18, t);

      // The flame: a teardrop, wide at the base and tapering upward.
      const cx = size / 2;
      const flameTop = s(0.2);
      const flameBottom = s(0.82);
      if (y >= flameTop && y <= flameBottom) {
        const u = (y - flameTop) / (flameBottom - flameTop);
        // Zero width at both ends. The exponent above 1 pushes the widest
        // point down to ~2/3, giving a sharp tip on top and a rounded base.
        const width = s(0.21) * Math.sin(Math.pow(u, 1.7) * Math.PI);
        const dist = Math.abs(x - cx);
        if (width > 0.5) {
          const edge = clamp((width - dist) / 2, 0, 1);
          // Hotter and whiter toward the base, cooler blue at the tip.
          const hot = clamp(u, 0, 1);
          r = lerp(r, lerp(150, 245, hot), edge);
          g = lerp(g, lerp(210, 250, hot), edge);
          b = lerp(b, lerp(255, 235, hot), edge);
        }
      }

      rgba[i] = Math.round(r);
      rgba[i + 1] = Math.round(g);
      rgba[i + 2] = Math.round(b);
      rgba[i + 3] = Math.round(clamp(bgAlpha, 0, 1) * 255);
    }
  }
  return rgba;
}

const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
const lerp = (a, b, t) => a + (b - a) * clamp(t, 0, 1);

/// Windows accepts PNG-compressed images inside an ICO container (Vista+).
function encodeIco(pngs) {
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2); // type: icon
  header.writeUInt16LE(pngs.length, 4);

  let offset = 6 + pngs.length * 16;
  const entries = [];
  for (const { size, data } of pngs) {
    const entry = Buffer.alloc(16);
    entry[0] = size >= 256 ? 0 : size;
    entry[1] = size >= 256 ? 0 : size;
    entry.writeUInt16LE(1, 4); // colour planes
    entry.writeUInt16LE(32, 6); // bits per pixel
    entry.writeUInt32BE(data.length, 8);
    entry.writeUInt32LE(data.length, 8);
    entry.writeUInt32LE(offset, 12);
    entries.push(entry);
    offset += data.length;
  }

  return Buffer.concat([header, ...entries, ...pngs.map((p) => p.data)]);
}

mkdirSync(OUT, { recursive: true });

const png = (size) => encodePng(size, draw(size));

const outputs = {
  "32x32.png": png(32),
  "128x128.png": png(128),
  "128x128@2x.png": png(256),
  "icon.png": png(512),
};

for (const [name, data] of Object.entries(outputs)) {
  writeFileSync(join(OUT, name), data);
}

writeFileSync(
  join(OUT, "icon.ico"),
  encodeIco([16, 32, 48, 64, 128, 256].map((size) => ({ size, data: png(size) }))),
);

console.log(`Wrote ${Object.keys(outputs).length + 1} icon files to ${OUT}`);
