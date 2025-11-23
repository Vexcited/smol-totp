import { hmac } from "@noble/hashes/hmac.js";
import { sha1 } from "@noble/hashes/legacy.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { base32 } from "@scure/base";

const dec2hex = (dec: number): string => Math.round(dec).toString(16);
const hex2dec = (hex: string): number => parseInt(hex, 16);

/**
 * Generate a TOTP based on the given settings.
 *
 * @param key HEX encoded base32 secret key.
 * @param time timestamp to use for the TOTP generation, defaults to now.
 * @param period seconds between each generation.
 * @param digits number of digits in the generated TOTP.
 * @returns a TOTP code.
 */
export const totp = (
  key: string,
  time = Date.now(),
  period = 30,
  digits = 6
): string => {
  time = Math.floor(time / 1000 / period);
  const t = dec2hex(time).padStart(16, "0");
  const k = base32.decode(key);
  const s = bytesToHex(hmac(sha1, k, hexToBytes(t)));
  const o = hex2dec(s.slice(-1)) * 2;
  const m = hex2dec(s.slice(o, o + 8)) & 0x7fffffff;
  return m.toString().slice(-digits);
};
