# obsideo-cloud

**Encrypted storage we can't read.** Save, browse, and sync whatever you want
from your terminal. Files are encrypted on your machine before they leave, so
Obsideo's gateway, coordinator, and storage providers only ever see ciphertext.
Your data lands on three independent providers (RF=3).

```
pip install obsideo-cloud
obsideo-cloud login    # email -> 3 GB free
obsideo-cloud          # open the shell (or just 'obsideo')
```

## Get started

```
$ obsideo-cloud login
Enter your email: you@example.com
Check your email for a verification code.
Enter verification code: 482913
You're all set. 3 GB free.
```

Login is handled by Obsideo's signup service at **`signup.obsideo.io`**: it emails
you a one-time code and provisions your free tier. There's no password - just your
email and a local key (see *How it works*).

Then either drop into the shell or run one-shot commands:

```
$ obsideo-cloud
obsideo:/ put ~/notes.txt
obsideo:/ ls
  [file] notes.txt  1.2 KB
obsideo:/ put ~/photos                       # a whole folder, uploaded recursively
obsideo:/ put "C:\My Files\tax return.pdf"   # paths with spaces: just quote them
obsideo:/ mkdir trip
obsideo:/ cd trip
obsideo:/trip/ put ~/cat.jpg
obsideo:/trip/ get cat.jpg ./downloaded.jpg
```

## Commands

| Command | Description |
|---|---|
| `obsideo-cloud login` | Sign up / log in with your email (3 GB free) |
| `ls [path]` | List files and folders |
| `cd <path>` / `pwd` | Move around / show location |
| `put <local> [name]` | Encrypt + upload a file, or a whole folder (recursive). `--no-encrypt` to store as-is |
| `get <remote> [local]` | Download + decrypt a file |
| `rm <remote>` | Delete a file |
| `mkdir <name>` | Create a folder |
| `info <remote>` | Show object metadata |
| `account` | Show storage used vs. your free quota |
| `sync push\|pull\|status` | Sync your local folder with Obsideo |
| `config [set k v]` | Show or change settings |

## How it works

`obsideo` is a thin front-end over the shared **`obsideo_core`** layer (storage
seam, signing identity, account crypto, email-OTP login). The `mlvault` ML
extension builds on the same core - build the core once, two front-ends.

- **Encryption:** AES-256-GCM with one account data key held locally at
  `~/.obsideo/data.key`. Copy that key to another machine and everything is
  readable there; lose it and the data is unrecoverable by design. Back it up.
- **Signing identity:** an Ed25519 key (`~/.obsideo/signing.key`) authorizes
  deletes (Principle 2 - the network can't delete your data without your
  signature). Generated locally; only the public half is ever sent.
- **Filename encryption:** on by default (`encrypt_names`). Each path component
  (folder names + filename) is encrypted on your machine with AES-SIV - deterministic,
  so `ls`/`cd` still list under the encrypted prefix and the client decrypts the
  returned tokens back to real names. Turn it off with `config set encrypt_names false`
  (interop/debug; existing objects aren't migrated).
- **What Obsideo sees:** ciphertext only - never a filename or a byte of content.
  Residual leaks (by design at this level): directory *structure* (depth, fan-out),
  object *sizes* (ciphertext ≈ plaintext), and object *counts*. Identical names
  encrypt to identical tokens, so Obsideo can tell two objects share a name - never
  what it is.

## License

MIT
