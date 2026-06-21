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

Then either drop into the shell or run one-shot commands:

```
$ obsideo-cloud
obsideo:/ put ~/notes.txt
obsideo:/ ls
  [file] notes.txt  1.2 KB
obsideo:/ mkdir photos
obsideo:/ cd photos
obsideo:/photos/ put ~/cat.jpg
obsideo:/photos/ get cat.jpg ./downloaded.jpg
```

## Commands

| Command | Description |
|---|---|
| `obsideo-cloud login` | Sign up / log in with your email (3 GB free) |
| `ls [path]` | List files and folders |
| `cd <path>` / `pwd` | Move around / show location |
| `put <local> [name]` | Encrypt + upload a file |
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
- **What Obsideo sees:** ciphertext and object key names. File *contents* are
  never readable by Obsideo. (Filenames/paths are currently stored in the clear,
  like most cloud storage; client-side name encryption is a planned option.)

## License

MIT
