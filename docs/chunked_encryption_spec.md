# Chunked content encryption (`obsideo-chunked-v1`) — format spec

So every Obsideo client (the browser app, the CLI, the SDK) writes and reads large
files **identically**. The CLI's reference implementation is
`obsideo_core/chunked.py`; the test vector below is checked by
`tests/test_chunked.py`.

## Why
The CLI's original format encrypts a file as one AES-256-GCM stream
(`nonce(12) || ct || tag(16)`). Browsers cannot run AES-GCM incrementally
(WebCrypto is one-shot, whole input in memory), so a browser cannot encrypt or
decrypt a large file in that format. This format seals the file as a sequence of
independently encrypted chunks, so any client can stream it with constant memory.

## Format
- **Key:** the account data key (32 bytes).
- Plaintext is cut into chunks of exactly `P = 1048576 - 28 = 1048548` bytes
  (last one shorter). Each plaintext chunk `i` is encrypted separately with
  AES-256-GCM → `ct_i || tag_i(16)`. The object's bytes are the concatenation of
  ciphertext chunks. **No header.**
- `file_nonce` = 8 random bytes per upload. `nonce_i (12 bytes) = file_nonce || BE32(i)`.
- `AAD_i = b"obsideo-chunked-v1" + BE32(i) + BE32(total_chunks)`.
- Parameters travel in the object's metadata:
  `metadata = {"enc": "obsideo-chunked-v1", "nonce": "<16 lowercase hex>", "chunks": "<total_chunks decimal>"}`.
- **Detection:** `metadata["enc"] == "obsideo-chunked-v1"` → chunked; key absent →
  legacy single-stream; any other value → refuse with a clear error
  ("unknown encryption format <value>; upgrade obsideo-cli"). Never guess.

`BE32(x)` is `x` as a 4-byte big-endian unsigned integer. The AAD binds every chunk
to its position and to the file's chunk count, so chunks cannot be reordered,
duplicated, or dropped from the end without a tag failing.

## Details the CLI implements
- **Chunk count** = `ceil(size / P)`, and **1 for an empty file** (one chunk of
  zero plaintext bytes, stored as a bare 16-byte tag), so every object, even an
  empty one, is authenticated.
- **Stored chunk size:** every ciphertext chunk except the last is `P + 16 =
  1048564` bytes; the last is `16 ..= 1048564` bytes.
- **Plaintext size** = `(total_chunks - 1) * P + (len(last ciphertext chunk) - 16)`
  = `object size - 16 * total_chunks`.
- **Readers must** verify each chunk's tag before releasing its plaintext, refuse
  an object whose size does not hold exactly `total_chunks` chunks, and discard
  already-written output if any later chunk fails (the CLI writes to a partial
  file and renames it into place only after the last tag verifies).
- **Metadata values are strict:** `nonce` is exactly 16 lowercase hex characters;
  `chunks` is a decimal integer from 1 to 2^32 - 1 with no sign, spaces or leading
  zeros. Metadata key names are matched case-insensitively (S3 metadata names are
  case-insensitive, and gateways return them in varying case).
- On the S3 interface the parameters appear as `x-amz-meta-enc`, `x-amz-meta-nonce`,
  `x-amz-meta-chunks` on GET and HEAD.

> **Open point, to settle before either client ships.** The design note this spec
> comes from also says "every ciphertext chunk except the last is exactly 1 MiB"
> and "plaintext size = (total_chunks - 1) * P + (len(last ct chunk) - 28)". With
> `ct_i || tag_i` and `P = 1048548`, a stored chunk is `P + 16 = 1048564` bytes,
> not 1 MiB, so encryption chunks do not line up with the network's 1 MiB merkle
> chunks. This document and the CLI follow the explicit construction (P and
> `ct_i || tag_i`). Keeping 1 MiB alignment needs either `P = 1048576 - 16` with
> `ct_i || tag_i`, or `P = 1048548` with each chunk stored as `nonce_i || ct_i || tag_i`.
> The test vector below pins the current choice; changing it changes the vector.

## Test vector
- Phrase: the BIP-39 English test phrase (`abandon` × 11, then `about`).
  `seed = PBKDF2-HMAC-SHA512(NFKD(phrase), "mnemonic", 2048, 64)`,
  `data key = HKDF-SHA256(ikm = seed, salt = none, info = "obsideo-phrase-v1/data-key", L = 32)`
  = `05d4e219677ac3fdbaa10e86b8ef2598c34edfa31ea8b4f14c670ca0ea8c95e3`.
- `file_nonce = 0000000000000001`.
- Plaintext: `2 MiB + 12345` = 2109497 bytes, byte `k` = `k mod 256`.

| Output | Value |
|---|---|
| total_chunks | 3 |
| stored chunk sizes | 1048564, 1048564, 12417 (object = 2109545 bytes) |
| SHA-256(object) | `e2bc7e26da4ac7b934a9865eb86e06acd8b3d8edc1aa77bfb730e64975786ca8` |
| SHA-256(chunk 0) | `22525a9e2536817b4402a3ad839799ca55ed70a6e060262414a56ae7687cb621` |
| merkle root (network's 1 MiB chunks) | `5f066a87bcc02e42e1b92ad517fef5928c4b1bf2968ebed4a80a535222f5f9615e698e3b4bef2ea895ba7c6c104b7fe990902a8ea8dd04811d7ebb28c381a9de` |
| metadata | `{"enc": "obsideo-chunked-v1", "nonce": "0000000000000001", "chunks": "3"}` |

The merkle root is the network's: the object split into 1 MiB chunks,
`leaf_i = SHA3-512(SHA-256(ASCII(str(i)) || ASCII(lowercase hex of chunk i)))`,
padded with 64-byte zero leaves to a power of two, `parent = SHA3-512(left || right)`,
a single leaf being the root.
