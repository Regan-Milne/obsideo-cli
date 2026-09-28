# Self-describing content encryption (`obsideo-object-v1`) — format spec

The one content format every Obsideo client (the Drive browser app, the CLI) writes
from 2026-09-29 on, and the format every client must read. The CLI's reference
implementation is `obsideo_core/objectv1.py`; the test vector below is checked by
`tests/test_objectv1.py`, and the browser must reproduce it byte for byte.

## Why this replaces `obsideo-chunked-v1`

Design principle 2 promises sovereign recovery: **your phrase plus any one live
storage provider holding your bytes is enough to get a file back**, with the
coordinator gone. `obsideo-chunked-v1` kept the per-file nonce and the chunk
count in the coordinator's metadata, so a stored object could not be opened
without the coordinator. This format puts every value a reader needs into the
object itself. The coordinator's metadata copy is a hint that lets a client pick
the reader without fetching the first bytes; it is never required.

It also gives every file its own key, derived one-way from the account key. A
share link can hand out that file key without revealing anything about the
account key, which is what makes revocable sharing possible without a second
encryption layer.

## Format

```
header (48 bytes, at offset 0)
  0   4   magic        "OBSD" (0x4F 0x42 0x53 0x44)
  4   1   version      0x01
  5   1   key mode     0x01 = file key derived from the account data key
  6   2   reserved     zero
  8   8   file_nonce   random per upload
  16  16  key_salt     random per upload
  32  4   BE32 total_chunks
  36  12  reserved     zero

file key   = HKDF-SHA256(ikm = account data key, salt = key_salt,
                         info = "obsideo-file-key-v1", L = 32)
nonce_i    = file_nonce || BE32(i)                     (12 bytes)
AAD_i      = header || BE32(i)                         (52 bytes)
chunk_i    = AES-256-GCM(file key, nonce_i, plaintext_i, AAD_i) = ct_i || tag_i(16)
object     = header || chunk_0 || chunk_1 || ... || chunk_{total-1}
```

- **Account data key:** 32 bytes, from the phrase as before
  (`HKDF-SHA256(seed, info = "obsideo-phrase-v1/data-key")`). It is never used
  to encrypt content directly; only the per-file key is.
- **Plaintext chunking:** chunk 0 holds `P0 = 1048576 - 48 - 16 = 1048512` bytes,
  every later chunk `P = 1048576 - 16 = 1048560` (the last one shorter).
  `total_chunks = 1` if `size <= P0`, else `1 + ceil((size - P0) / P)`.
- **Empty file rule:** a zero-byte file is one chunk holding only a tag: the
  object is 64 bytes (header + tag). Every object, even an empty one, is
  authenticated.
- **Alignment:** `header || chunk_0` is exactly the network's 1 MiB merkle chunk
  0 when full, and `chunk_i` is merkle chunk `i` for `i >= 1`. A ranged fetch of
  merkle chunk 0 decrypts on its own; any other merkle chunk needs only the
  48-byte header. Object size = `48 + size + 16 * total_chunks`; the chunk count
  implied by a stored object of `n` bytes is `ceil(n / 1048576)`; plaintext size =
  `n - 48 - 16 * total_chunks`.
- **Reserved bytes** are written as zero. Readers ignore them; they are
  authenticated through the AAD, so they cannot be altered undetected.
- **Detection.** `metadata["enc"] == "obsideo-object-v1"` selects this reader;
  the reader then verifies the magic and version itself. With no metadata at all
  (offline recovery from a raw provider blob) the magic at offset 0 decides:
  `"OBSD"` + version 1 is this format, anything else is the legacy single stream
  (`nonce(12) || ct || tag(16)` under the account data key). A different
  version or key mode is refused with an "upgrade" message, never guessed.
- **Metadata** written alongside: `{"enc": "obsideo-object-v1"}` and nothing else
  (on the S3 interface, `x-amz-meta-enc`).
- **Readers must** verify each chunk's tag before releasing its plaintext,
  refuse an object whose size does not hold exactly `total_chunks` chunks, and
  discard already-written output if any later chunk fails (the CLI writes to a
  partial file and renames it into place only after the last tag verifies).

`BE32(x)` is `x` as a 4-byte big-endian unsigned integer.

## Recovery without the coordinator

`obsideo recover <stored-object-file> <output> --key <64 hex>` (or `--phrase
"<12 words>"`) turns a raw stored object into the file, using nothing but the
bytes and the key. This is the sovereign-recovery drill for this format and a
permanent regression test. What it does not solve: fetching the raw bytes from a
provider still needs a coordinator-issued download token today
(`E2E_ENCRYPTION_MODEL.md` §7.2 lists that as v2's known limitation); this format
removes the *decryption* dependency, which was the new one.

## Older formats

- `obsideo-chunked-v1` (Drive uploads between 2026-09-28 03:10Z and the
  switch): still read by every client. Drive re-keys them into this format in
  the background the next time the owner signs in. Spec kept at
  `docs/chunked_encryption_spec.md` for reading only.
- Legacy single stream (CLI `put` before this change, Drive uploads before
  2026-09-28): no `enc` metadata, `nonce(12) || ct || tag(16)` under the account
  data key. Self-contained already, so it stays readable and is not migrated.

## Test vector

- Phrase: the BIP-39 English test phrase (`abandon` × 11, then `about`).
  `seed = PBKDF2-HMAC-SHA512(NFKD(phrase), "mnemonic", 2048, 64)`,
  `data key = HKDF-SHA256(ikm = seed, salt = none, info = "obsideo-phrase-v1/data-key", L = 32)`
  = `05d4e219677ac3fdbaa10e86b8ef2598c34edfa31ea8b4f14c670ca0ea8c95e3`.
- `file_nonce = 0000000000000001`, `key_salt = 000102030405060708090a0b0c0d0e0f`.
- Plaintext: `2 MiB + 12345` = 2109497 bytes, byte `k` = `k mod 256`.

| Output | Value |
|---|---|
| total_chunks | 3 |
| header (hex) | `4f425344010100000000000000000001000102030405060708090a0b0c0d0e0f00000003000000000000000000000000` |
| file key | `2efd38f3f158bddcaf2bcc4ed6feee57cfef09e45ab9a69a6a872ceec51c7c2c` |
| stored piece sizes | 1048576 (header + chunk 0), 1048576, 12441 (object = 2109593 bytes) |
| SHA-256(object) | `388b301d4843885f4cc377faf537ca92fb3937641b4446b2661f923a8152cfc0` |
| SHA-256(merkle chunk 0) | `2a1804321ad136205af4594828353b4fedda5de392f88d73b18f5873446e9e34` |
| merkle root | `6924b4b6df51624eee35a6a5f7b5131e755ae56ab1fd86a3e3c5b3b2a7beee9b810b00aaf15aab4a54b6c3620dbb5ae221c7587a3704ee06192686d54fd6dddf` |
| metadata | `{"enc": "obsideo-object-v1"}` |

The merkle root is the network's, over the object's 1 MiB chunks:
`leaf_i = SHA3-512(SHA-256(ASCII(str(i)) || ASCII(lowercase hex of chunk i)))`,
padded with 64-byte zero leaves to a power of two, `parent = SHA3-512(left || right)`,
a single leaf being the root.
