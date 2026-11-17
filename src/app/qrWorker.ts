import jsQR from "jsqr";

/* =========================
   QR Worker
   ========================= */

/* Decodes the image and searches it for QR codes, away from the page. A picture full of detail can keep */
/* the search busy for many seconds, so it runs here, where it can be stopped and never freezes the page. */
/* qrImage.ts sets the limits and sends them with the image. The image never leaves this worker. */
interface Request {
  file: Blob;
  width: number;
  height: number;
  maxCodes: number;
  budgetMs: number;
}

const SEARCH = { inversionAttempts: "attemptBoth" } as const;

/* How the picture is cut up when the whole of it gives nothing: columns by rows. The search can lose */
/* codes that sit close together, and each part holds fewer of them. */
const GRIDS = [
  [2, 1],
  [1, 2],
  [2, 2],
  [3, 1],
  [1, 3],
  [3, 2],
  [2, 3],
];

/* The pixels of one part of the picture, as a picture of its own. */
function crop(image: ImageData, x: number, y: number, width: number, height: number) {
  const part = new Uint8ClampedArray(width * height * 4);
  for (let row = 0; row < height; row++) {
    const from = ((y + row) * image.width + x) * 4;
    part.set(image.data.subarray(from, from + width * 4), row * width * 4);
  }
  return part;
}

/* Looks for one code in the whole picture, then in its parts. The offsets say where the part was. If the */
/* time is up it stops and says so. */
function findCode(image: ImageData, deadline: number) {
  const whole = jsQR(image.data, image.width, image.height, SEARCH);
  if (whole) return { code: whole, left: 0, top: 0, timedOut: false };

  for (const [columns, rows] of GRIDS) {
    const width = Math.floor(image.width / columns);
    const height = Math.floor(image.height / rows);
    for (let row = 0; row < rows; row++) {
      for (let column = 0; column < columns; column++) {
        if (performance.now() > deadline) return { code: null, left: 0, top: 0, timedOut: true };
        const left = column * width;
        const top = row * height;
        const code = jsQR(crop(image, left, top, width, height), width, height, SEARCH);
        if (code) return { code, left, top, timedOut: false };
      }
    }
  }
  return { code: null, left: 0, top: 0, timedOut: false };
}

/* Paints over a code that has been read, so that the next search finds a different one. */
function blank(image: ImageData, corners: { x: number; y: number }[]) {
  const pad = 3;
  const left = Math.max(0, Math.floor(Math.min(...corners.map((corner) => corner.x))) - pad);
  const right = Math.min(image.width - 1, Math.ceil(Math.max(...corners.map((corner) => corner.x))) + pad);
  const top = Math.max(0, Math.floor(Math.min(...corners.map((corner) => corner.y))) - pad);
  const bottom = Math.min(image.height - 1, Math.ceil(Math.max(...corners.map((corner) => corner.y))) + pad);
  for (let y = top; y <= bottom; y++) {
    for (let x = left; x <= right; x++) {
      image.data.fill(255, (y * image.width + x) * 4, (y * image.width + x) * 4 + 4);
    }
  }
}

async function read({ file, width, height, maxCodes, budgetMs }: Request) {
  const deadline = performance.now() + budgetMs;

  /* A picture that is too big was already refused, so this only shrinks one that is a little large. */
  const bitmap = await createImageBitmap(file, { resizeWidth: width, resizeHeight: height, resizeQuality: "high" });
  const context = new OffscreenCanvas(width, height).getContext("2d", { willReadFrequently: true });
  if (!context) throw new Error("No canvas.");
  context.drawImage(bitmap, 0, 0, width, height);
  bitmap.close();
  const pixels = context.getImageData(0, 0, width, height);

  const codes: string[] = [];
  let incomplete = false;
  for (let attempt = 0; attempt < maxCodes; attempt++) {
    if (performance.now() > deadline) {
      incomplete = true;
      break;
    }
    const { code, left, top, timedOut } = findCode(pixels, deadline);
    if (timedOut) incomplete = true;
    if (!code) break;
    if (code.data && !codes.includes(code.data)) codes.push(code.data);
    const where = code.location;
    blank(
      pixels,
      [where.topLeftCorner, where.topRightCorner, where.bottomLeftCorner, where.bottomRightCorner].map((corner) => ({ x: corner.x + left, y: corner.y + top })),
    );
  }
  return { codes, incomplete };
}

self.onmessage = async (event: MessageEvent<Request>) => {
  try {
    self.postMessage({ ok: true, ...(await read(event.data)) });
  } catch {
    self.postMessage({ ok: false });
  }
};
