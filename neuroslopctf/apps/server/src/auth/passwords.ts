import { randomBytes, scrypt, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";

const derive = promisify(scrypt) as (
  password: string,
  salt: Buffer,
  length: number,
) => Promise<Buffer>;

const KEY_LENGTH = 32;

export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16);
  const hash = await derive(password, salt, KEY_LENGTH);

  return `scrypt$${salt.toString("base64")}$${hash.toString("base64")}`;
}

export async function verifyPassword(
  password: string,
  stored: string,
): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 3 || parts[0] !== "scrypt") {
    return false;
  }

  const salt = decodeBase64(parts[1]!, 16);
  const expected = decodeBase64(parts[2]!, KEY_LENGTH);
  if (!salt || !expected) {
    return false;
  }

  const actual = await derive(password, salt, KEY_LENGTH);
  return timingSafeEqual(actual, expected);
}

function decodeBase64(encoded: string, length: number): Buffer | null {
  if (encoded.length !== Math.ceil(length / 3) * 4) {
    return null;
  }

  const decoded = Buffer.from(encoded, "base64");
  return decoded.length === length && decoded.toString("base64") === encoded
    ? decoded
    : null;
}
