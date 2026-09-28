> **Superseded 2026-09-29 by [`obsideo-object-v1`](object_format_v1.md).** No client
> writes this format any more. It is kept so every client can still *read* the
> objects Drive wrote between 2026-09-28 03:10Z and the switch; Drive re-keys
> them into the new format in the background. The reason it was replaced: the
> nonce and chunk count lived only in the coordinator's metadata, so a stored
> object could not be opened without the coordinator, which breaks sovereign
> recovery (design principle 2).

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
- Plaintext is cut into chunks of exactly `P = 1048576 - 16 = 1048560` bytes
  (last one shorter). Each plaintext chunk `i` is encrypted separately with
  AES-256-GCM → `ct_i || tag_i(16)`, so every ciphertext chunk except the last is
  exactly 1 MiB (`P + 16 = 1048576`). The object's bytes are the concatenation of
  ciphertext chunks. **No header**, and no per-chunk nonce: nonces are derived.
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
- **Chunk count** = `ceil(size / P)` for a non-empty file.
- **Empty file rule:** a zero-byte file is **1 chunk**: zero plaintext bytes,
  stored as a bare 16-byte tag, with `"chunks": "1"`. Every object, even an empty
  one, is authenticated, and the gateway never sees an empty body.
- **Stored chunk size:** every ciphertext chunk except the last is `P + 16 =
  1048576` bytes (1 MiB); the last is 16 to 1048576 bytes. Ciphertext chunk `i`
  is therefore exactly the network's 1 MiB merkle chunk `i`, so a ranged fetch
  of one merkle chunk decrypts on its own.
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
| stored chunk sizes | 1048576, 1048576, 12393 (object = 2109545 bytes) |
| SHA-256(object) | `5c394de4fcfb785410d7ec7909c6119cace800e130cba938029983f94f496ad4` |
| SHA-256(chunk 0) | `d32faa972573ff89c2e0250d9fa9ca65396cc61d28f464fcbebfc75ada88aeae` |
| merkle root | `358f99ff00d692d7e0c8e85d43345576cf7b8a27a5ddd22ef37aed9fac7fd6cd221fb04015fff13e0d7e03f669cf0be30f4a6ae518f683e7828f4c62a55481c9` |
| metadata | `{"enc": "obsideo-chunked-v1", "nonce": "0000000000000001", "chunks": "3"}` |

The merkle root is the network's, over the object's 1 MiB chunks (which here are
exactly the ciphertext chunks):
`leaf_i = SHA3-512(SHA-256(ASCII(str(i)) || ASCII(lowercase hex of chunk i)))`,
padded with 64-byte zero leaves to a power of two, `parent = SHA3-512(left || right)`,
a single leaf being the root.
