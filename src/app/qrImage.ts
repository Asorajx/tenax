/* =========================
   QR Image
   ========================= */

/* Reads QR codes out of an image on this PC. The image is only decoded in memory, in a worker (see */
/* qrWorker.ts). It is never shown, saved or sent, and only the text of the codes leaves this file. The */
/* image may be anything, so its size is checked from its header before it is decoded, a picture that is */
/* too big is refused, and a search that takes too long is stopped. */
const MAX_BYTES = 10 * 1024 * 1024;
const MAX_PIXELS = 40_000_000;
/* A bigger picture is shrunk to this on its longest side before it is searched. */
const MAX_SIDE = 2000;
/* The most codes read from one image. It must match MAX_CODES in src-tauri/src/qr_scam/mod.rs. */
export const MAX_CODES = 5;
/* The worker stops searching after this long and says so. If it does not answer in the longer time, */
/* which means it is stuck inside one search, it is shut down. */
const BUDGET_MS = 5000;
const STUCK_MS = 25000;

/* A problem with the image itself, with a message that can be shown as it is. */
export class ImageProblem extends Error {}

/* The size written in the header of a PNG or JPEG, read without decoding the picture. It is null for */
/* any other kind of file, and for a header that is cut short or wrong. */
export function imageSize(bytes: Uint8Array): { width: number; height: number } | null {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);

  /* PNG: the 8-byte signature, then the IHDR block, which starts with the width and height. */
  if (bytes.length >= 24 && view.getUint32(0) === 0x89504e47 && view.getUint32(4) === 0x0d0a1a0a && view.getUint32(12) === 0x49484452) {
    return { width: view.getUint32(16), height: view.getUint32(20) };
  }

  /* JPEG: markers one after another until the one that holds the size. */
  if (bytes.length >= 4 && view.getUint16(0) === 0xffd8) {
    let at = 2;
    while (at + 4 <= bytes.length) {
      if (bytes[at] !== 0xff) return null;
      const marker = bytes[at + 1];
      /* Padding, and markers that have no length after them. */
      if (marker === 0xff) {
        at += 1;
        continue;
      }
      if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
        at += 2;
        continue;
      }
      /* 0xc0 to 0xcf start a frame, except 0xc4, 0xc8 and 0xcc, which are something else. */
      if (marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc) {
        if (at + 9 > bytes.length) return null;
        return { height: view.getUint16(at + 5), width: view.getUint16(at + 7) };
      }
      const length = view.getUint16(at + 2);
      if (length < 2) return null;
      at += 2 + length;
    }
  }
  return null;
}

/* Only one image is read at a time. Starting another shuts the first one's worker down. */
let current: Worker | null = null;

/* The text of every QR code in the image, up to MAX_CODES. It is untrusted text: it is shown and */
/* checked, and never opened. "incomplete" means the search ran out of time, so there may be more. */
export async function readQrCodes(file: Blob): Promise<{ codes: string[]; incomplete: boolean }> {
  if (file.size > MAX_BYTES) throw new ImageProblem("That image is too large. Use one under 10 MB.");
  const size = imageSize(new Uint8Array(await file.slice(0, 1024 * 1024).arrayBuffer()));
  if (!size) throw new ImageProblem("Use a PNG or JPEG image.");
  if (size.width < 1 || size.height < 1) throw new ImageProblem("Tenax could not read that image.");
  if (size.width * size.height > MAX_PIXELS) throw new ImageProblem("That image is too large to read.");

  const scale = Math.min(1, MAX_SIDE / Math.max(size.width, size.height));
  const width = Math.max(1, Math.round(size.width * scale));
  const height = Math.max(1, Math.round(size.height * scale));

  current?.terminate();
  const worker = new Worker(new URL("./qrWorker.ts", import.meta.url), { type: "module" });
  current = worker;

  return new Promise((resolve, reject) => {
    const stuck = window.setTimeout(() => {
      worker.terminate();
      reject(new ImageProblem("Reading the image took too long, so it was not searched. That does not mean it is safe."));
    }, STUCK_MS);
    const finish = () => {
      window.clearTimeout(stuck);
      worker.terminate();
      if (current === worker) current = null;
    };
    worker.onmessage = (event: MessageEvent<{ ok: boolean; codes?: string[]; incomplete?: boolean }>) => {
      finish();
      if (event.data.ok) resolve({ codes: event.data.codes ?? [], incomplete: Boolean(event.data.incomplete) });
      else reject(new ImageProblem("Tenax could not read that image."));
    };
    worker.onerror = () => {
      finish();
      reject(new ImageProblem("Tenax could not read that image."));
    };
    worker.postMessage({ file, width, height, maxCodes: MAX_CODES, budgetMs: BUDGET_MS });
  });
}
