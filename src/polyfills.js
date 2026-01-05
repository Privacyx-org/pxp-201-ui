// src/polyfills.js
export async function ensureNodeGlobals() {
  // Buffer (needed by some libs)
  if (typeof globalThis.Buffer === "undefined") {
    const mod = await import("buffer");
    globalThis.Buffer = mod.Buffer;
  }

  // (optional) process — disabled for now (not required for pxp201)
  // If needed later, we’ll polyfill it safely.
}

