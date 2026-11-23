"use strict";

/* Perceptual image hashes computed from the browser-decoded image, with the
 * definitions used by the imagehash library: pHash is the sign of the 8x8
 * lowest DCT-II frequencies of a 32x32 greyscale copy against their median;
 * dHash compares horizontally adjacent pixels of a 9x8 greyscale copy. Both
 * are 64 bits, written as 16 hex digits, most significant bit first.
 * The image is hashed as displayed (EXIF orientation applied), which equals
 * imagehash over PIL's ImageOps.exif_transpose(image). The browser's
 * downscaling filter differs from PIL's LANCZOS, so dHash (9x8) can differ
 * from the library by some bits; pHash (32x32) usually matches.
 */

(function () {
  const G = typeof window !== "undefined" ? window.GARBAGE : null;

  function toHex(bits) {
    let hex = "";
    for (let index = 0; index < bits.length; index += 4) {
      hex += ((bits[index] << 3) | (bits[index + 1] << 2) | (bits[index + 2] << 1) | bits[index + 3]).toString(16);
    }
    return hex;
  }

  /* ITU-R 601-2 luma, as PIL's convert("L"). */
  function greyscale(rgba, count) {
    const grey = new Float64Array(count);
    for (let index = 0; index < count; index += 1) {
      const offset = index * 4;
      grey[index] = Math.round((rgba[offset] * 299 + rgba[offset + 1] * 587 + rgba[offset + 2] * 114) / 1000);
    }
    return grey;
  }

  function dhashFromGrey(grey) {
    const bits = [];
    for (let y = 0; y < 8; y += 1) {
      for (let x = 0; x < 8; x += 1) bits.push(grey[y * 9 + x + 1] > grey[y * 9 + x] ? 1 : 0);
    }
    return toHex(bits);
  }

  /* Unnormalised DCT-II (scipy.fftpack.dct type 2) of every row or column. */
  function dct1d(input, size) {
    const output = new Float64Array(size);
    for (let k = 0; k < size; k += 1) {
      let sum = 0;
      for (let n = 0; n < size; n += 1) sum += input[n] * Math.cos((Math.PI * k * (2 * n + 1)) / (2 * size));
      output[k] = 2 * sum;
    }
    return output;
  }

  function phashFromGrey(grey) {
    const size = 32;
    const columns = new Float64Array(size * size);
    const column = new Float64Array(size);
    for (let x = 0; x < size; x += 1) {
      for (let y = 0; y < size; y += 1) column[y] = grey[y * size + x];
      const transformed = dct1d(column, size);
      for (let y = 0; y < size; y += 1) columns[y * size + x] = transformed[y];
    }
    const low = [];
    for (let y = 0; y < 8; y += 1) {
      const transformed = dct1d(columns.subarray(y * size, y * size + size), size);
      for (let x = 0; x < 8; x += 1) low.push(transformed[x]);
    }
    const sorted = [...low].sort((a, b) => a - b);
    const median = (sorted[31] + sorted[32]) / 2;
    // Coefficients equal to the median up to rounding noise (flat images)
    // count as not greater, as they do in the reference implementation.
    const tolerance = 1e-9 * Math.max(...low.map(Math.abs), 1);
    return toHex(low.map((value) => (value > median + tolerance ? 1 : 0)));
  }

  async function decodedGrey(bitmap, width, height) {
    const canvas = document.createElement("canvas");
    canvas.width = width;
    canvas.height = height;
    const context = canvas.getContext("2d", { willReadFrequently: true });
    context.imageSmoothingEnabled = true;
    context.imageSmoothingQuality = "high";
    context.drawImage(bitmap, 0, 0, width, height);
    return greyscale(context.getImageData(0, 0, width, height).data, width * height);
  }

  /* {phash, dhash} for an image File or Blob, or null when the browser
     cannot decode it. */
  async function compute(file) {
    let bitmap;
    try {
      // The image as displayed: EXIF orientation applied (browsers apply it
      // regardless), so a rotated copy saved without EXIF still matches.
      bitmap = await createImageBitmap(file, { imageOrientation: "from-image" });
    } catch (error) {
      return null;
    }
    try {
      return {
        phash: phashFromGrey(await decodedGrey(bitmap, 32, 32)),
        dhash: dhashFromGrey(await decodedGrey(bitmap, 9, 8)),
      };
    } finally {
      bitmap.close?.();
    }
  }

  if (G) G.imageHash = { compute, phashFromGrey, dhashFromGrey };
  if (typeof module !== "undefined") module.exports = { phashFromGrey, dhashFromGrey };
})();
