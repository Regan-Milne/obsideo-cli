"""obsideo - the general Obsideo CLI.

Save, browse, and sync whatever you want - encrypted on your machine before it
leaves, so Obsideo can't read it. An interactive shell plus one-shot commands.

    obsideo login                 sign up / log in (email -> 3 GB free)
    obsideo                       start the interactive shell
    obsideo ls / put / get ...    run a single command
"""

import cmd
import os
import shlex
import sys
import urllib.error
import urllib.request
import json
from pathlib import Path

from obsideo_core import config, crypto, identity, login, storage


def _unquote(s: str) -> str:
    """Strip one layer of matching surrounding quotes."""
    s = s.strip()
    if len(s) >= 2 and s[0] in "\"'" and s[-1] == s[0]:
        return s[1:-1]
    return s


def _tokens(arg: str) -> list[str]:
    """Tokenize a command line respecting quotes, Windows-path-safe (backslashes
    are not escape characters). 'put "C:\\a b\\f.png" name' -> ['C:\\a b\\f.png','name']."""
    try:
        toks = shlex.split(arg, posix=False)
    except ValueError:
        toks = arg.split()
    return [_unquote(t) for t in toks]


def _human(n: int | None) -> str:
    if n is None:
        return "?"
    f = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if f < 1024 or unit == "TB":
            return f"{f:.0f} {unit}" if unit == "B" else f"{f:.1f} {unit}"
        f /= 1024


# ── Operator notices (server-driven broadcasts) ──────────────────────────────

_SEEN_FILE = config.CONFIG_DIR / "seen_notices"
_SEV = {  # severity -> (marker, ansi); ansi only emitted on a TTY
    "info":   ("·",  "\033[36m"),    # cyan
    "action": ("!",  "\033[33m"),    # yellow
    "urgent": ("!!", "\033[1;31m"),  # bold red
}
_RESET = "\033[0m"


def _load_seen() -> set:
    try:
        return set(_SEEN_FILE.read_text().split())
    except OSError:
        return set()


def _mark_seen(ids: list) -> None:
    if not ids:
        return
    try:
        config.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(_SEEN_FILE, "a") as f:
            f.write("\n".join(ids) + "\n")
    except OSError:
        pass


def show_notices() -> None:
    """Print any unseen operator broadcasts to stderr, once each. Strictly
    best-effort: only on an interactive TTY, never touches stdout, and swallows
    every error so it can never break or slow a real command in a script."""
    if not sys.stdout.isatty() or os.environ.get("OBSIDEO_NO_NOTICES"):
        return
    try:
        req = urllib.request.Request(
            f"{config.signup_url()}/v1/notices",
            headers={"User-Agent": config.USER_AGENT},
        )
        with urllib.request.urlopen(req, timeout=4) as resp:
            notices = json.loads(resp.read().decode()).get("notices", [])
    except Exception:
        return
    if not notices:
        return
    seen = _load_seen()
    shown = []
    for n in notices:
        nid = str(n.get("id"))
        if nid in seen:
            continue
        marker, color = _SEV.get((n.get("severity") or "info").lower(), _SEV["info"])
        print(f"{color}{marker} Obsideo:{_RESET} {n.get('body', '').strip()}", file=sys.stderr)
        shown.append(nid)
    _mark_seen(shown)


# ── Operator tooling: broadcast a message to all users ────────────────────────

def run_admin(argv: list) -> int:
    """`obsideo admin broadcast [--severity info|action|urgent] [--ttl SECONDS] "message"`
    Authors a notice all users will see in their CLI. Requires the coord admin
    secret in OBSIDEO_ADMIN_SECRET (operator-only; never shipped or stored)."""
    if not argv or argv[0] != "broadcast":
        print('Usage: obsideo admin broadcast [--severity info|action|urgent] '
              '[--ttl SECONDS] "message"', file=sys.stderr)
        return 2
    severity, ttl, words, rest = "info", None, [], argv[1:]
    i = 0
    while i < len(rest):
        if rest[i] == "--severity" and i + 1 < len(rest):
            severity, i = rest[i + 1], i + 2
        elif rest[i] == "--ttl" and i + 1 < len(rest):
            ttl, i = rest[i + 1], i + 2
        else:
            words.append(rest[i]); i += 1
    body = " ".join(words).strip()
    if not body:
        print("A message body is required.", file=sys.stderr)
        return 2
    secret = os.environ.get("OBSIDEO_ADMIN_SECRET", "").strip()
    if not secret:
        print("Set OBSIDEO_ADMIN_SECRET (the coord admin secret) to broadcast.", file=sys.stderr)
        return 2
    payload = {"body": body, "severity": severity}
    if ttl is not None:
        try:
            payload["ttl_seconds"] = int(ttl)
        except ValueError:
            print("--ttl must be an integer number of seconds.", file=sys.stderr)
            return 2
    req = urllib.request.Request(
        f"{config.signup_url()}/internal/messages",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "User-Agent": config.USER_AGENT,
                 "X-Admin-Secret": secret},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            out = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        detail = e.read().decode()[:200]
        print(f"Broadcast failed: HTTP {e.code} {detail}", file=sys.stderr)
        return 1
    except urllib.error.URLError as e:
        print(f"Broadcast failed: {e.reason}", file=sys.stderr)
        return 1
    print(f"Broadcast sent (id {out.get('id')}, severity {severity}).")
    return 0


def run_login(url: str | None = None) -> bool:
    """Interactive email-OTP login. Returns True on success."""
    url = url or config.signup_url()
    email = input("Enter your email: ").strip()
    if not email:
        print("Email is required.")
        return False
    print("Sending a verification code...", end="", flush=True)
    try:
        login.start(email, url)
    except login.LoginError as e:
        print(f"\nCouldn't start signup: {e}")
        return False
    print(" sent.")
    print(f"Check {email} for a verification code (it may be in spam).")
    code = input("Enter verification code: ").strip()
    print("Verifying + provisioning storage...", end="", flush=True)
    try:
        creds = login.verify(email, code, url)
    except login.LoginError as e:
        print(f"\nVerification failed: {e}")
        return False
    print(" done.")
    storage.reset_client()
    # Make sure the data key exists + nudge the user to back it up.
    crypto.data_key()
    print(f"\nYou're all set. {creds.get('quota_gb', 3)} GB free.")
    if not creds.get("gateway_registered", True):
        print("Note: storage activation is finishing rollout; if an upload fails, retry shortly.")
    print("Your files are encrypted with a local key. Back it up:")
    print(f"  {crypto.DATA_KEY_FILE}")
    print("Type 'obsideo' to open the shell, or 'obsideo put <file>' to store something.")
    return True


class ObsideoShell(cmd.Cmd):
    intro = ("\n  Obsideo - encrypted storage we can't read.\n"
             "  Type 'help' for commands, 'exit' to quit.\n")
    prompt = "obsideo:/ "

    def __init__(self):
        super().__init__()
        self._cwd = ""  # S3 key prefix; "" = root
        self._refresh_prompt()

    # ── path helpers ────────────────────────────────────────────────────────
    def _refresh_prompt(self):
        self.prompt = f"obsideo:/{self._cwd} "

    def _resolve(self, name: str) -> str:
        if name.startswith("/"):
            return name.lstrip("/")
        return f"{self._cwd}{name}"

    def _require_login(self) -> bool:
        if not config.is_logged_in():
            print("You're not logged in. Run 'login' (or 'obsideo login').")
            return False
        return True

    # ── login ───────────────────────────────────────────────────────────────
    def do_login(self, arg):
        """Sign up / log in with your email (email -> 3 GB free)."""
        run_login()
        self._cwd = ""
        self._refresh_prompt()

    # ── ls ──────────────────────────────────────────────────────────────────
    def do_ls(self, arg):
        """List files and folders. Usage: ls [path]"""
        if not self._require_login():
            return
        target = _unquote(arg.strip())
        prefix = self._resolve(target) if target else self._cwd
        try:
            resp = storage.list_prefix(prefix)
        except Exception as e:
            print(f"Error: {e}")
            return
        for d in resp["folders"]:
            print(f"  [dir]  {d}/")
        for f in resp["files"]:
            print(f"  [file] {f['name']}  {_human(f['size'])}")
        if not resp["folders"] and not resp["files"]:
            print("  (empty)")

    # ── cd / pwd ──────────────────────────────────────────────────────────────
    def do_cd(self, arg):
        """Change directory. Usage: cd <path> | cd .. | cd /"""
        path = _unquote(arg.strip())
        if not path or path == "/":
            self._cwd = ""
        elif path == "..":
            trimmed = self._cwd.rstrip("/")
            self._cwd = trimmed[:trimmed.rfind("/") + 1] if "/" in trimmed else ""
        elif path.startswith("/"):
            self._cwd = path.lstrip("/")
            if self._cwd and not self._cwd.endswith("/"):
                self._cwd += "/"
        else:
            self._cwd = f"{self._cwd}{path}"
            if not self._cwd.endswith("/"):
                self._cwd += "/"
        self._refresh_prompt()
        print(f"  /{self._cwd}")

    def do_pwd(self, arg):
        """Print current directory."""
        print(f"  /{self._cwd}")

    # ── put / upload ──────────────────────────────────────────────────────────
    def do_put(self, arg):
        """Upload a file, or a whole folder recursively.

        Each file is encrypted on your machine (AES-256-GCM) before upload, so
        Obsideo only ever stores ciphertext. A folder uploads all of its files,
        preserving structure under <name>/.

        Usage:
          put <local_path> [remote_name] [--no-encrypt]

        Examples:
          put report.pdf                store as report.pdf
          put report.pdf q3.pdf         store under a different name
          put ./photos                  upload the whole folder -> photos/...
          put notes.txt --no-encrypt    upload as-is (NOT encrypted)
        """
        if not self._require_login():
            return
        parts = _tokens(arg)
        if not parts:
            print("Usage: put <local_path> [remote_name] [--no-encrypt]")
            return
        no_encrypt = "--no-encrypt" in parts
        parts = [p for p in parts if p != "--no-encrypt"]
        local = Path(parts[0]).expanduser()
        if not local.exists():
            print(f"Not found: {local}")
            return
        base = parts[1] if len(parts) > 1 else local.name
        do_encrypt = config.load_config().get("encrypt", True) and not no_encrypt

        if local.is_dir():
            self._put_folder(local, base, do_encrypt)
        else:
            self._put_file(local, self._resolve(base), do_encrypt)

    do_upload = do_put

    def _put_file(self, local: Path, key: str, do_encrypt: bool):
        try:
            raw = local.read_bytes()
        except OSError as e:
            print(f"  Error reading {local}: {e}")
            return
        body = crypto.encrypt(raw) if do_encrypt else raw
        verb = "Encrypting + uploading" if do_encrypt else "Uploading"
        print(f"  {verb} {key.rsplit('/', 1)[-1]} ({_human(len(raw))})...")
        try:
            storage.put(key, body)
            print(f"  Stored: /{key}")
        except Exception as e:
            print(f"  Error: {e}")

    def _put_folder(self, folder: Path, base: str, do_encrypt: bool):
        files = [f for f in sorted(folder.rglob("*")) if f.is_file()]
        if not files:
            print(f"  (empty folder: {folder})")
            return
        verb = "Encrypting + uploading" if do_encrypt else "Uploading"
        print(f"  {verb} folder {base}/ ({len(files)} file(s))...")
        ok = 0
        for f in files:
            rel = f.relative_to(folder).as_posix()
            key = self._resolve(f"{base}/{rel}")
            try:
                raw = f.read_bytes()
                body = crypto.encrypt(raw) if do_encrypt else raw
                storage.put(key, body)
                ok += 1
                print(f"    {rel}  ({_human(len(raw))})")
            except Exception as e:
                print(f"    {rel}  - FAILED: {e}")
        print(f"  Stored {ok}/{len(files)} file(s) under /{self._resolve(base)}/")

    # ── get / download ────────────────────────────────────────────────────────
    def do_get(self, arg):
        """Download a file. Usage: get <remote_file> [local_path]"""
        if not self._require_login():
            return
        parts = _tokens(arg)
        if not parts:
            print("Usage: get <remote_file> [local_path]")
            return
        key = self._resolve(parts[0])
        local = Path(parts[1]).expanduser() if len(parts) > 1 else Path(Path(parts[0]).name)
        print(f"  Downloading /{key}...")
        try:
            blob = storage.get(key)
        except Exception as e:
            print(f"  Error: {e}")
            return
        try:
            raw = crypto.decrypt(blob)
        except Exception:
            raw = blob  # stored unencrypted, or wrong key
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_bytes(raw)
        print(f"  Saved to: {local} ({_human(len(raw))})")

    do_download = do_get

    # ── rm ──────────────────────────────────────────────────────────────────
    def do_rm(self, arg):
        """Delete a file. Usage: rm <remote_file>"""
        if not self._require_login():
            return
        name = _unquote(arg.strip())
        if not name:
            print("Usage: rm <remote_file>")
            return
        key = self._resolve(name)
        try:
            storage.delete(key)
            print(f"  Deleted: /{key}")
        except Exception as e:
            print(f"  Error: {e}")

    # ── mkdir ─────────────────────────────────────────────────────────────────
    def do_mkdir(self, arg):
        """Create a folder. Usage: mkdir <name>"""
        if not self._require_login():
            return
        name = _unquote(arg.strip())
        if not name:
            print("Usage: mkdir <name>")
            return
        try:
            created = storage.mkdir(self._resolve(name))
            print(f"  Created: /{created}")
        except Exception as e:
            print(f"  Error: {e}")

    # ── info ──────────────────────────────────────────────────────────────────
    def do_info(self, arg):
        """Show object metadata. Usage: info <remote_file>"""
        if not self._require_login():
            return
        name = _unquote(arg.strip())
        if not name:
            print("Usage: info <remote_file>")
            return
        meta = storage.head(self._resolve(name))
        if not meta:
            print("  Not found.")
            return
        print(f"  size: {_human(meta['size'])}")
        if meta.get("last_modified"):
            print(f"  modified: {meta['last_modified']}")

    # ── account ───────────────────────────────────────────────────────────────
    def do_account(self, arg):
        """Show your plan: storage used vs. your free quota."""
        if not self._require_login():
            return
        usage = _fetch_usage()
        print()
        print("  -- Obsideo account --------------------------")
        print("     Plan:  Free")
        if usage:
            used, quota = usage["used_bytes"], usage["quota_bytes"]
            pct = usage.get("percent_used", (used / quota if quota else 0))
            print(f"     Used:  {_human(used)} / {_human(quota)} ({pct*100:.1f}%)")
            bar_len = 30
            filled = int(bar_len * min(pct, 1.0))
            print(f"     [{'#'*filled}{'-'*(bar_len-filled)}]")
            if pct >= 0.8:
                print("     You're near your limit - reply to any Obsideo email to upgrade.")
        else:
            print("     (usage unavailable - is the account service reachable?)")
        print("  ---------------------------------------------")
        print()

    # ── sync ──────────────────────────────────────────────────────────────────
    def do_sync(self, arg):
        """Sync your local folder with Obsideo. Usage: sync push|pull|status"""
        if not self._require_login():
            return
        from obsideo import sync as sync_mod
        sub = arg.strip().lower()
        if sub == "push":
            n = sync_mod.push()
            print(f"  Done. {n} file(s) pushed.")
        elif sub == "pull":
            n = sync_mod.pull()
            print(f"  Done. {n} file(s) pulled.")
        elif sub == "status":
            s = sync_mod.sync_status()
            for f in s["to_push"]:
                print(f"    + {f}  (push)")
            for f in s["to_pull"]:
                print(f"    - {f}  (pull)")
            for f in s["synced"]:
                print(f"    = {f}")
            if not any(s.values()):
                print("  Nothing to sync.")
        else:
            print("Usage: sync push|pull|status")

    # ── config ────────────────────────────────────────────────────────────────
    def do_config(self, arg):
        """Show or set config. Usage: config | config set <key> <value>"""
        parts = arg.strip().split(None, 2)
        if not parts:
            for k, v in config.load_config().items():
                print(f"  {k}: {v}")
            print(f"  config_dir: {config.CONFIG_DIR}")
            return
        if parts[0] == "set" and len(parts) == 3:
            key, value = parts[1], parts[2]
            cfg = config.load_config()
            if key == "encrypt":
                value = value.lower() in ("true", "1", "yes", "on")
            cfg[key] = value
            config.save_config(cfg)
            print(f"  {key} = {value}")
        else:
            print("Usage: config | config set <key> <value>")

    # ── exit ──────────────────────────────────────────────────────────────────
    def do_exit(self, arg):
        """Exit."""
        print("Bye.")
        return True

    do_quit = do_exit

    def do_EOF(self, arg):
        print()
        return True

    def emptyline(self):
        pass


def _fetch_usage() -> dict | None:
    token = config.account_token()
    if not token:
        return None
    try:
        req = urllib.request.Request(
            f"{config.signup_url()}/v1/account/usage",
            headers={"Authorization": f"Bearer {token}", "User-Agent": config.USER_AGENT},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


def main():
    argv = sys.argv[1:]

    # Standard --help / -h (cmd.Cmd would otherwise read "--help" as a command).
    if argv and argv[0] in ("-h", "--help", "help"):
        ObsideoShell().onecmd("help")
        return

    # `obsideo login` is interactive and handled specially.
    if argv and argv[0] == "login":
        ok = run_login()
        sys.exit(0 if ok else 1)

    # `obsideo admin ...` is operator tooling, not a shell command.
    if argv and argv[0] == "admin":
        sys.exit(run_admin(argv[1:]))

    # Surface any pending operator broadcasts (no-op unless interactive).
    show_notices()

    shell = ObsideoShell()

    # One-shot: `obsideo ls`, `obsideo put file.txt`, etc.
    if argv:
        shell.onecmd(" ".join(argv))
        return

    # First-run nudge: not logged in -> offer login.
    if not config.is_logged_in():
        print("Welcome to Obsideo - encrypted storage we can't read.")
        if input("Log in / sign up now? (Y/n): ").strip().lower() in ("", "y", "yes"):
            if not run_login():
                return
        else:
            print("Run 'obsideo login' when you're ready.")
            return

    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        print("\nBye.")


if __name__ == "__main__":
    main()
