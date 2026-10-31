/**
 * Crypto constant-table recognizer for mapped PE images.
 *
 * The image is indexed by RVA: `img[rva]` is the byte at relative virtual
 * address `rva`.  Signatures intentionally use the canonical byte order for
 * each table.  For tables whose published representation is an array of
 * 32-bit words, both the big-endian and little-endian encodings are included
 * so that either common compiler layout is recognized.
 */

export type CryptoKind =
  | "aes-sbox"
  | "aes-inv-sbox"
  | "aes-rcon"
  | "sha256-k"
  | "sha256-h"
  | "md5-t"
  | "crc32-table"
  | "blowfish-p"
  | "blowfish-s"
  | "chacha-const"
  | "tea-delta"
  | "xtea-key"
  | "rc4-state"
  | "base64-alphabet"
  | "rijndael-mix"
  | "salsa-const"
  | "custom";

export type CryptoHit = {
  kind: CryptoKind;
  name: string;
  rva: number;
  address: string;
  confidence: number;
  note: string;
};

export const kCryptoSignatures: readonly {
  kind: CryptoKind;
  name: string;
  bytes: Uint8Array;
  note: string;
  confidence: number;
}[] = [
  {
    kind: "aes-sbox",
    name: "AES forward S-box",
    bytes: Uint8Array.from([
      0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
      0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    ]),
    note: "First 16 bytes of the standard AES (Rijndael) forward substitution box.",
    confidence: 0.99,
  },
  {
    kind: "aes-inv-sbox",
    name: "AES inverse S-box",
    bytes: Uint8Array.from([
      0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
      0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    ]),
    note: "First 16 bytes of the standard AES inverse substitution box.",
    confidence: 0.99,
  },
  {
    kind: "aes-rcon",
    name: "AES round constants",
    bytes: Uint8Array.from([
      0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    ]),
    note: "AES key-schedule round constants (rcon).",
    confidence: 0.97,
  },
  {
    kind: "sha256-k",
    name: "SHA-256 K table",
    bytes: Uint8Array.from([
      0x42, 0x8a, 0x2f, 0x98, 0x71, 0x37, 0x44, 0x91,
      0xb5, 0xc0, 0xfb, 0xcf, 0xe9, 0xb5, 0xdb, 0xa5,
    ]),
    note: "First four SHA-256 round constants (K[0..3]), big-endian.",
    confidence: 0.97,
  },
  {
    kind: "sha256-h",
    name: "SHA-256 initial hash",
    bytes: Uint8Array.from([
      0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85,
      0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a,
      0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c,
      0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19,
    ]),
    note: "SHA-256 initial hash value H[0..7], eight big-endian words.",
    confidence: 0.94,
  },
  {
    kind: "md5-t",
    name: "MD5 sine table",
    bytes: Uint8Array.from([
      0x78, 0xa4, 0x6a, 0xd7, 0x56, 0xb7, 0xc7, 0xe8,
      0xdb, 0x70, 0x20, 0x24, 0xee, 0xce, 0xbd, 0xc1,
    ]),
    note: "First four MD5 T-table words in the usual little-endian layout.",
    confidence: 0.94,
  },
  {
    kind: "md5-t",
    name: "MD5 sine table (big-endian words)",
    bytes: Uint8Array.from([
      0xd7, 0x6a, 0xa4, 0x78, 0xe8, 0xc7, 0xb7, 0x56,
      0x24, 0x20, 0x70, 0xdb, 0xc1, 0xbd, 0xce, 0xee,
    ]),
    note: "First four MD5 T-table words in big-endian byte order.",
    confidence: 0.92,
  },
  {
    kind: "crc32-table",
    name: "CRC-32 table (0xEDB88320)",
    bytes: Uint8Array.from([
      0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07, 0x77,
      0xdc, 0xed, 0x0e, 0xee, 0xba, 0x51, 0x09, 0x99,
    ]),
    note: "First four entries of the reflected CRC-32 table, little-endian words.",
    confidence: 0.97,
  },
  {
    kind: "crc32-table",
    name: "CRC-32 table (0xEDB88320, big-endian words)",
    bytes: Uint8Array.from([
      0x00, 0x00, 0x00, 0x00, 0x77, 0x07, 0x30, 0x96,
      0xee, 0x0e, 0xed, 0xdc, 0x99, 0x09, 0x51, 0xba,
    ]),
    note: "First four entries of the reflected CRC-32 table, big-endian words.",
    confidence: 0.92,
  },
  {
    kind: "blowfish-p",
    name: "Blowfish P-array",
    bytes: Uint8Array.from([
      0x88, 0x6a, 0x3f, 0x24, 0xd3, 0x08, 0xa3, 0x85,
      0x2e, 0x8a, 0x19, 0x13, 0x44, 0x73, 0x70, 0x03,
      0x22, 0x38, 0x09, 0xa4, 0xd0, 0x31, 0x9f, 0x29,
      0x98, 0xfa, 0x2e, 0x08, 0x89, 0x6c, 0x4e, 0xec,
    ]),
    note: "First eight Blowfish P-array words in the usual little-endian layout.",
    confidence: 0.97,
  },
  {
    kind: "blowfish-p",
    name: "Blowfish P-array (big-endian words)",
    bytes: Uint8Array.from([
      0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3,
      0x13, 0x19, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x44,
      0xa4, 0x09, 0x38, 0x22, 0x29, 0x9f, 0x31, 0xd0,
      0x08, 0x2e, 0xfa, 0x98, 0xec, 0x4e, 0x6c, 0x89,
    ]),
    note: "First eight Blowfish P-array words in big-endian byte order.",
    confidence: 0.93,
  },
  {
    kind: "blowfish-s",
    name: "Blowfish S-box S0",
    bytes: Uint8Array.from([
      0xa6, 0x0b, 0x31, 0xd1, 0xac, 0xb5, 0xdf, 0x98,
      0xdb, 0x72, 0xfd, 0x2f, 0xb7, 0xfd, 0x1a, 0xd0,
    ]),
    note: "First four Blowfish S0 words in the usual little-endian layout.",
    confidence: 0.94,
  },
  {
    kind: "blowfish-s",
    name: "Blowfish S-box S0 (big-endian words)",
    bytes: Uint8Array.from([
      0xd1, 0x31, 0x0b, 0xa6, 0x98, 0xdf, 0xb5, 0xac,
      0x2f, 0xfd, 0x72, 0xdb, 0xd0, 0x1a, 0xdf, 0xb7,
    ]),
    note: "First four Blowfish S0 words in big-endian byte order.",
    confidence: 0.91,
  },
  {
    kind: "chacha-const",
    name: "ChaCha20 constant",
    bytes: Uint8Array.from([
      0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33,
      0x32, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6b,
    ]),
    note: 'ASCII "expand 32-byte k" ChaCha20 constant.',
    confidence: 0.99,
  },
  {
    kind: "tea-delta",
    name: "TEA/XTEA delta",
    bytes: Uint8Array.from([0xb9, 0x79, 0x37, 0x9e]),
    note: "0x9E3779B9 TEA/XTEA sum delta in little-endian layout.",
    confidence: 0.93,
  },
  {
    kind: "tea-delta",
    name: "TEA/XTEA delta (big-endian)",
    bytes: Uint8Array.from([0x9e, 0x37, 0x79, 0xb9]),
    note: "0x9E3779B9 TEA/XTEA sum delta in big-endian layout.",
    confidence: 0.91,
  },
  {
    kind: "rc4-state",
    name: "RC4 state initialization",
    bytes: Uint8Array.from([0x00, 0x01, 0x02, 0x03]),
    note: "Beginning of the identity permutation used to initialize RC4 state.",
    confidence: 0.65,
  },
  {
    kind: "base64-alphabet",
    name: "Base64 alphabet",
    bytes: Uint8Array.from([
      0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
      0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
      0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
      0x59, 0x5a, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
      0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e,
      0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
      0x77, 0x78, 0x79, 0x7a, 0x30, 0x31, 0x32, 0x33,
      0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x2b, 0x2f,
    ]),
    note: "Standard RFC 4648 Base64 alphabet.",
    confidence: 0.99,
  },
  {
    kind: "rijndael-mix",
    name: "Rijndael/GF(2^8) table",
    bytes: Uint8Array.from([
      0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
      0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
      0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
      0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    ]),
    note: "Canonical Rijndael/GF(2^8) lookup-table prefix.",
    confidence: 0.96,
  },
  {
    kind: "salsa-const",
    name: "Salsa20 constant",
    bytes: Uint8Array.from([
      0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33,
      0x32, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6b,
    ]),
    note: 'ASCII "expand 32-byte k" Salsa20 constant.',
    confidence: 0.99,
  },
];

function findAll(haystack: Uint8Array, needle: Uint8Array): number[] {
  const hits: number[] = [];
  if (needle.length === 0 || needle.length > haystack.length) return hits;

  const last = haystack.length - needle.length;
  for (let start = 0; start <= last; start++) {
    if (haystack[start] !== needle[0]) continue;
    let matches = true;
    for (let i = 1; i < needle.length; i++) {
      if (haystack[start + i] !== needle[i]) {
        matches = false;
        break;
      }
    }
    if (matches) hits.push(start);
  }
  return hits;
}

function formatAddress(rva: number, base?: bigint): string {
  if (base === undefined) return `0x${rva.toString(16)}`;
  return `0x${(base + BigInt(rva)).toString(16)}`;
}

/** Scan an entire mapped image for every known crypto constant table. */
export function scanCrypto(img: Uint8Array, base?: bigint): CryptoHit[] {
  const hits: CryptoHit[] = [];

  for (const signature of kCryptoSignatures) {
    for (const rva of findAll(img, signature.bytes)) {
      hits.push({
        kind: signature.kind,
        name: signature.name,
        rva,
        address: formatAddress(rva, base),
        confidence: signature.confidence,
        note: signature.note,
      });
    }
  }

  hits.sort((a, b) => a.rva - b.rva || a.kind.localeCompare(b.kind) || a.name.localeCompare(b.name));
  return hits;
}

/** Return crypto-table hits whose confidence meets the requested threshold. */
export function findCryptoConstants(
  img: Uint8Array,
  base?: bigint,
  minConfidence = 0.5,
): CryptoHit[] {
  return scanCrypto(img, base).filter((hit) => hit.confidence >= minConfidence);
}
