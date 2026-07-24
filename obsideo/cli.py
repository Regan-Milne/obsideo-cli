"""obsideo - the general Obsideo CLI.

Save, browse, and sync whatever you want - encrypted on your machine before it
leaves, so Obsideo can't read it. An interactive shell plus one-shot commands.

    obsideo login                 sign up / log in (email -> 12 GB free)
    obsideo                       start the interactive shell
    obsideo ls / put / get ...    run a single command
"""

import cmd
import os
import shlex
import subprocess
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


def _gb(n) -> str:
    """Format a GB count for display: drop a trailing .0 (2.0 -> '2', 2.5 -> '2.5')."""
    try:
        f = float(n)
    except (TypeError, ValueError):
        return str(n)
    return str(int(f)) if f == int(f) else f"{f:g}"


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
        with urllib.request.urlopen(req, timeout=4, context=config.ssl_context()) as resp:
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


# ── Branding banner + version self-check ──────────────────────────────────────

_BANNER = r"""
    /\
   /  \    OBSIDEO DRIVE
   \  /    encrypted storage not even we can read
    \/
"""

_BANNER_SHOWN = False


def _chrome_enabled() -> bool:
    """Banner/prompt are human chrome: only on an interactive stdout, and never
    when OBSIDEO_NO_BANNER / NO_COLOR is set. Keeps stdout clean for agents/pipes."""
    if os.environ.get("OBSIDEO_NO_BANNER") or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def show_banner() -> None:
    """Branded ASCII banner to stderr, once per process, TTY-gated."""
    global _BANNER_SHOWN
    if _BANNER_SHOWN or not _chrome_enabled():
        return
    _BANNER_SHOWN = True
    print(f"\033[36m{_BANNER}\033[0m", file=sys.stderr)


def _usage_bar(pct: float, cells: int = 10) -> str:
    filled = min(cells, max(0, round(pct * cells)))
    return "#" * filled + "-" * (cells - filled)


def show_status() -> None:
    """One-line account status (tier · usage bar · upgrade hint) to stderr, TTY-gated.
    Makes a network call, so it's shown at session start / post-login only."""
    if not _chrome_enabled() or not config.is_logged_in():
        return
    usage = _fetch_account_info() or _fetch_usage()
    if not usage:
        return
    used, quota = usage.get("used_bytes", 0), usage.get("quota_bytes", 0)
    if not quota:
        return  # no quota to show a bar against; account command shows raw usage
    pct = usage.get("percent_used")
    if pct is None:
        pct = (used / quota) if quota else 0.0
    hint = "  ·  \033[36mupgrade\033[0m for more" if pct >= 0.8 else ""
    print(f"\033[2mFree\033[0m [{_usage_bar(pct)}] {_human(used)} of {_human(quota)}{hint}",
          file=sys.stderr)


def _parse_version(v: str) -> tuple:
    """Lenient dotted-version → comparable int tuple. '0.2.10' > '0.2.9'."""
    out = []
    for part in v.split("."):
        digits = ""
        for ch in part:
            if ch.isdigit():
                digits += ch
            else:
                break
        out.append(int(digits) if digits else 0)
    return tuple(out)


def _latest_pypi_version() -> str | None:
    try:
        req = urllib.request.Request(
            f"https://pypi.org/pypi/{config.PACKAGE}/json",
            headers={"User-Agent": config.USER_AGENT},
        )
        with urllib.request.urlopen(req, timeout=15, context=config.ssl_context()) as resp:
            return json.loads(resp.read().decode())["info"]["version"]
    except Exception:
        return None


def check_for_update() -> None:
    """On interactive init: if PyPI has a newer obsideo-cli, offer to update now.
    TTY-gated (never prompts agents/scripts), fail-silent (a network hiccup never
    blocks startup). Disable with OBSIDEO_NO_UPDATE_CHECK."""
    if not sys.stdout.isatty() or os.environ.get("OBSIDEO_NO_UPDATE_CHECK"):
        return
    current = config.VERSION
    latest = _latest_pypi_version()
    if not latest or _parse_version(latest) <= _parse_version(current):
        return
    print(f"\n\033[36mUpdate available: {current} -> {latest}\033[0m", file=sys.stderr)
    try:
        ans = input("Update now? [Y/n]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print(file=sys.stderr)
        return
    manual = f"pip install -U --no-cache-dir {config.PACKAGE}"
    if ans not in ("", "y", "yes"):
        print(f"Skipped. Update later with:  {manual}", file=sys.stderr)
        return
    if sys.platform == "win32":
        # Windows file-locks the running obsideo.exe, so pip can't replace it from
        # inside a live session (WinError 32). Hand over the one command to run.
        print(f"\nWindows can't replace the CLI while it's running. To finish, close\n"
              f"obsideo and run:\n    {manual}", file=sys.stderr)
        return
    print(f"Updating to {latest}...", file=sys.stderr)
    try:
        rc = subprocess.run(
            [sys.executable, "-m", "pip", "install", "-U", "--no-cache-dir", config.PACKAGE]
        ).returncode
    except Exception as e:
        print(f"Update failed: {e}\nTry manually:  {manual}", file=sys.stderr)
        return
    if rc == 0:
        print(f"\nUpdated to {latest}. Restart `obsideo` to use the new version.", file=sys.stderr)
        sys.exit(0)
    print(f"Update didn't complete. Try:  pip install -U {config.PACKAGE}", file=sys.stderr)


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
        with urllib.request.urlopen(req, timeout=15, context=config.ssl_context()) as resp:
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


LOGIN_USAGE = """\
Usage: obsideo login [options]

  With no options, prompts for everything (the human path).

Options:
  --email <address>   account email; skips the email prompt
  --code <123456>     the 6-digit code from that inbox; skips the code prompt
  --source <label>    attribution recorded on the account (e.g. your tool name)
  --referral <code>   a friend's referral code, +1 GB
  --json              print a machine-readable receipt instead of prose
  -h, --help          show this

Driving it without a terminal (two calls, because the code arrives by email):
  obsideo login --email you@example.com --source my-agent --json
  obsideo login --email you@example.com --code 123456 --json

With no terminal and a missing required value, this exits with an error naming
the flag rather than blocking on a prompt nobody can answer."""

_LOGIN_FLAGS = {"--email": "email", "--code": "code", "--source": "source",
                "--referral": "referral"}


def _parse_login_args(args: list[str]) -> tuple[dict, str | None]:
    """Tiny hand-rolled parser. Returns (kwargs, error)."""
    opts: dict = {}
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-h", "--help"):
            opts["help"] = True
            i += 1
        elif a == "--json":
            opts["json_out"] = True
            i += 1
        elif a in _LOGIN_FLAGS:
            if i + 1 >= len(args) or args[i + 1].startswith("--"):
                return {}, f"{a} needs a value."
            opts[_LOGIN_FLAGS[a]] = args[i + 1]
            i += 2
        else:
            return {}, f"Unknown option for login: {a}"
    return opts, None


class NonInteractive(Exception):
    """A required value was missing and there is no terminal to ask on."""


def _ask(prompt: str, provided: str | None, flag: str, *, required: bool = True) -> str:
    """Return a supplied value, else prompt for it, else fail loudly.

    An agent or CI job running `obsideo login` used to hit a bare input() and
    either hang or die with a raw EOFError traceback. Failing with a message
    naming the flag is always better than either.

    isatty() is checked first as a fast path but is NOT trusted on its own:
    on Windows shells it can report a terminal when stdin is redirected. The
    EOFError catch is what actually makes this reliable everywhere.
    """
    if provided is not None:
        return provided.strip()
    if sys.stdin.isatty():
        try:
            # Prompt on stderr, not via input()'s own argument, which writes to
            # stdout. Keeps stdout parseable for --json callers.
            print(prompt, end="", flush=True, file=sys.stderr)
            return input().strip()
        except (EOFError, KeyboardInterrupt):
            pass
    elif required:
        raise NonInteractive(f"{flag} is required when there is no terminal to prompt on")
    else:
        return ""
    if required:
        raise NonInteractive(f"{flag} is required when there is no terminal to prompt on")
    return ""


def run_login(url: str | None = None, *, email: str | None = None,
              code: str | None = None, source: str | None = None,
              referral: str | None = None, json_out: bool = False) -> bool:
    """Email-OTP login. Interactive when run by a human, flag-driven for agents.

    Fully interactive (no flags) behaves exactly as it always has. Supplying
    --email alone performs step one only (send the code) and returns, because
    the code arrives out of band; supplying --email and --code performs the
    verification. That two-call shape is what lets a caller with no terminal
    drive the whole flow.
    """
    url = url or config.signup_url()
    # In --json mode the human narration goes to stderr so stdout carries only
    # the receipt and a caller can pipe it straight into a parser.
    say = (lambda *a, **k: print(*a, **k, file=sys.stderr)) if json_out else print
    try:
        email = _ask("Enter your email: ", email, "--email")
    except NonInteractive as e:
        say(f"{e}. See `obsideo login --help`.")
        return False
    if not email:
        say("Email is required.")
        return False
    say("Sending a verification code...", end="", flush=True)
    try:
        login.start(email, url, source=source)
    except login.LoginError as e:
        say(f"\nCouldn't start signup: {e}")
        return False
    say(" sent.")
    say(f"Check {email} for a verification code (it may be in spam).")
    try:
        code = _ask("Enter verification code: ", code, "--code")
        # Optional friend's referral code -> +1 GB (13 GB instead of 12).
        referral_code = _ask("Referral code from a friend (optional, Enter to skip): ",
                             referral, "--referral", required=False)
    except NonInteractive:
        # There is no way to ask for the code here, and the code only arrives by
        # email anyway. This is the normal path for a caller without a terminal:
        # stop cleanly at step one, having actually sent the code, and tell the
        # caller how to finish. Success, not failure.
        if json_out:
            print(json.dumps({"ok": True, "stage": "code_sent", "email": email,
                              "next": f"obsideo login --email {email} --code <6-digit code>"},
                             indent=2))
        else:
            print(f"\nCode sent. Finish with:\n  obsideo login --email {email} --code <code>")
        return True
    say("Verifying + provisioning storage...", end="", flush=True)
    try:
        creds = login.verify(email, code, url, referral_code=referral_code or None)
    except login.LoginError as e:
        say(f"\nVerification failed: {e}")
        return False
    say(" done.")
    storage.reset_client()
    # Make sure the data key exists + nudge the user to back it up.
    crypto.data_key()
    if json_out:
        # A receipt a caller can parse. Deliberately omits the secret key:
        # it is already persisted to the credentials file, and printing it
        # would put it in logs and terminal scrollback.
        print(json.dumps({
            "ok": True,
            "stage": "provisioned",
            "email": email,
            "quota_gb": creds.get("quota_gb"),
            "endpoint": creds.get("endpoint"),
            "region": creds.get("region"),
            "bucket": creds.get("bucket"),
            "access_key": creds.get("access_key"),
            "account_exists": creds.get("account_exists"),
            "credentials_file": str(config.CREDENTIALS_FILE),
            "data_key_file": str(crypto.DATA_KEY_FILE),
        }, indent=2))
        return True
    print(f"\nYou're all set. {creds.get('quota_gb', 12)} GB free.")
    if referral_code:
        if creds.get("referral_applied"):
            print(f"Referral applied - enjoy the extra space! (code {referral_code.upper()})")
        else:
            print(f"That referral code ({referral_code}) wasn't recognized, so no bonus was added.")
    if not creds.get("gateway_registered", True):
        print("Note: storage activation is finishing rollout; if an upload fails, retry shortly.")
    print("Your files are encrypted with a local key. Back it up:")
    print(f"  {crypto.DATA_KEY_FILE}")
    # Create the sync folder now so it's ready (never make the user mkdir it).
    try:
        from obsideo import sync as _sync
        sd = _sync.ensure_sync_dir()
        print(f"Your sync folder is ready (drop files here, then `sync push`):\n  {sd}")
    except Exception:
        pass
    print("Type 'obsideo' to open the shell, or 'obsideo put <file>' to store something.")
    return True


class ObsideoShell(cmd.Cmd):
    intro = (
        "\n  Obsideo - your content is encrypted before it leaves your machine.\n\n"
        "  Common commands:\n"
        "    put <file> / get <name>     upload / download\n"
        "    ls / cd / mkdir             browse your files\n"
        "    sync push / pull / status   mirror your sync folder\n"
        "    account                     your plan and usage\n"
        "    refer                       invite friends for free space\n"
        "    about / faq / messages      learn more / team news\n\n"
        "  Type 'help <command>' for details (e.g. 'help sync'), or 'exit' to quit.\n"
    )
    prompt = "obsideo:/ "

    def __init__(self):
        super().__init__()
        self._cwd = ""  # S3 key prefix; "" = root
        self._refresh_prompt()

    def precmd(self, line: str) -> str:
        # Tolerate a leading "obsideo " typed out of habit inside the shell
        # (e.g. "obsideo ls" -> "ls"), so it doesn't error with Unknown syntax.
        stripped = line.lstrip()
        if stripped.lower().startswith("obsideo "):
            return stripped[len("obsideo "):]
        return line

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
        """Sign up / log in with your email (email -> 12 GB free)."""
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
        """Show your account: plan, storage used, and where your files/keys live."""
        if not self._require_login():
            return
        from obsideo import sync as sync_mod
        # Usage + quota for any account via the gateway (works with just the S3
        # creds); fall back to the signup-service token, then to a storage-only
        # count - so this always shows something useful and never nags to log in.
        info = _fetch_account_info() or (_fetch_usage() if config.account_token() else None)
        print()
        print("  -- Obsideo account --------------------------")
        if info:
            tier = (info.get("tier") or "free").replace("testdrive", "Free").title()
            print(f"     Plan:  {tier}")
            used = info.get("used_bytes", 0)
            quota = info.get("quota_bytes", 0)
            if quota:
                pct = used / quota
                bar_len = 30
                filled = int(bar_len * min(pct, 1.0))
                print(f"     Used:  {_human(used)} / {_human(quota)} ({pct*100:.1f}%)")
                print(f"            [{'#'*filled}{'-'*(bar_len-filled)}]")
                if pct >= 0.8:
                    print("     Near your limit - reply to any Obsideo email to upgrade.")
            else:
                print(f"     Used:  {_human(used)}")
            if info.get("object_count"):
                print(f"     Files: {info['object_count']} object(s)")
            if info.get("days_remaining"):
                print(f"     Renews/expires in {info['days_remaining']} day(s)")
        else:
            print("     Plan:  Free")
            try:
                used, n = storage.total_usage()
                print(f"     Used:  {_human(used)} across {n} file(s)")
            except Exception:
                print("     Used:  (couldn't read storage just now)")
        # Referral summary (only for email-login accounts; pre-shim accounts have
        # no signup token and just don't show this line).
        ref = _fetch_referral() if config.account_token() else None
        if ref:
            if ref.get("active"):
                print(f"     Referrals: code {ref['code']} - {ref['active']} active, "
                      f"+{_gb(ref.get('earned_gb', 0))} GB earned  ('refer' for more)")
            else:
                print(f"     Referrals: code {ref['code']} - invite friends for free space ('refer')")
        print(f"     Bucket: {storage.bucket()}")
        print(f"     Sync folder: {sync_mod.ensure_sync_dir()}")
        print(f"     Keys: {config.CONFIG_DIR}  (back up data.key)")
        print("  ---------------------------------------------")
        print()

    # ── about / faq / messages ────────────────────────────────────────────────
    def do_about(self, arg):
        """What Obsideo is."""
        print("""
  OBSIDEO DRIVE - content encrypted on your machine before upload.

  Your files are encrypted on your device (AES-256-GCM) before they ever leave
  it, then stored across three providers (RF=3). Obsideo's servers
  only ever see ciphertext - never your filenames, never your data.

  - Free: 12 GB, no card, no expiry.
  - Your keys live only on your machine (~/.obsideo). Back up data.key - lose it
    and the data is unrecoverable by design. That's the point: not even we can read it.
  - Install / update:  pip install -U obsideo-cli      More:  https://obsideo.io
""")

    def do_faq(self, arg):
        """Frequently asked questions."""
        print("""
  -- Obsideo FAQ --

  Q: Can Obsideo read my files?
  A: No. They're encrypted on your device before upload; we only store ciphertext.

  Q: What's free?
  A: 12 GB, no credit card, no expiry.

  Q: What if I lose my key?
  A: Your key is ~/.obsideo/data.key - back it up. Without it the data can't be
     decrypted by anyone, including us.

  Q: Two folders - what's the difference?
  A: ~/.obsideo  = your keys + settings (don't touch).
     ~/obsideo-sync = your SYNC folder - files you put here sync with `sync push`.

  Q: What does `sync` do?
  A: Mirrors your sync folder to/from the cloud. `sync push` uploads new/changed
     files, `sync pull` downloads, `sync status` shows what's pending. It's manual
     (you run it) and covers files in the top of the folder.

  Q: How do I change settings (sync folder, encryption)?
  A: `config` shows them; `config set sync_dir <path>` / `config set encrypt_names false`.

  Q: More space?
  A: Invite friends with `refer` - they get +1 GB, you get +2 GB once they
     upload. Or reply to any Obsideo email to upgrade.

  Q: Updating?
  A: pip install -U obsideo-cli  - the CLI also nudges you when an update is out.
""")

    def do_messages(self, arg):
        """Messages from the Obsideo team."""
        try:
            req = urllib.request.Request(
                f"{config.signup_url()}/v1/notices",
                headers={"User-Agent": config.USER_AGENT},
            )
            with urllib.request.urlopen(req, timeout=10, context=config.ssl_context()) as resp:
                notices = json.loads(resp.read().decode()).get("notices", [])
        except Exception:
            print("\n  Couldn't reach the message service - try again shortly.\n")
            return
        if not notices:
            print("\n  No messages from the Obsideo team right now.\n")
            return
        print("\n  -- Messages from the Obsideo team --")
        for n in notices:
            print(f"   - {n.get('body', '').strip()}")
        print()

    # ── refer ─────────────────────────────────────────────────────────────────
    def do_refer(self, arg):
        """Invite friends for free space. Usage: refer

        Share your code: each friend who joins with it gets +1 GB, and you get
        +2 GB once they actually upload something. No limit."""
        if not self._require_login():
            return
        if not config.account_token():
            print(
                "\n  Referrals need an email login. Run 'login' to sign up / sign in"
                "\n  with your email, then 'refer' shows your invite code.\n"
            )
            return
        info = _fetch_referral()
        if not info:
            print("\n  Couldn't load your referral info just now - try again shortly.\n")
            return

        each = info.get("owner_bonus_gb_each", 2)
        redeemer = info.get("redeemer_bonus_gb", 1)
        print()
        print("  -- Invite friends, get free space --------------------------")
        print(f"     Your code:  {info['code']}")
        print(f"     Share it: a friend runs `obsideo login` and enters your code.")
        print(f"     They get +{_gb(redeemer)} GB; you get +{_gb(each)} GB once they upload.")
        print()
        invited = info.get("invited", 0)
        active = info.get("active", 0)
        pending = info.get("pending", 0)
        earned = info.get("earned_gb", 0)
        if invited:
            print(f"     Invited: {invited}   Active: {active}   Pending upload: {pending}")
            print(f"     Earned so far: +{_gb(earned)} GB   (your quota: {_gb(info.get('quota_gb', 0))} GB)")
        else:
            print("     No referrals yet - share your code to start earning.")
        if info.get("newly_credited"):
            n = info["newly_credited"]
            print(f"     ✨ {n} friend(s) just activated - +{_gb(n*each)} GB added!")
        print("  ------------------------------------------------------------")
        print("  Bonuses are a promotional perk; Obsideo reserves the right to change")
        print("  or end the program and to revoke bonuses for abuse.")
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
            if key in ("encrypt", "encrypt_names"):
                value = value.lower() in ("true", "1", "yes", "on")
            cfg[key] = value
            config.save_config(cfg)
            print(f"  {key} = {value}")
        else:
            print("Usage: config | config set <key> <value>")

    # ── exit ──────────────────────────────────────────────────────────────────
    def do_exit(self, arg):
        """Exit."""
        print("adios amigo")
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
        with urllib.request.urlopen(req, timeout=15, context=config.ssl_context()) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


def _fetch_referral() -> dict | None:
    """Referral code + stats from the signup service (Bearer account token). Also
    triggers the server-side lazy credit check for any friend who just became
    active. Returns None for accounts without a signup token (e.g. pre-shim
    accounts) or if the service is unreachable — callers handle that gracefully."""
    token = config.account_token()
    if not token:
        return None
    try:
        req = urllib.request.Request(
            f"{config.signup_url()}/v1/account/referral",
            headers={"Authorization": f"Bearer {token}", "User-Agent": config.USER_AGENT},
        )
        with urllib.request.urlopen(req, timeout=20, context=config.ssl_context()) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


def _fetch_account_info() -> dict | None:
    """Usage + quota for the calling account via the gateway's SigV4-authed
    /v1/account. Works for ANY account using only the S3 creds we already have
    (no signup-service token needed). Returns {used_bytes, quota_bytes, tier,
    object_count, days_remaining, ...} or None if unavailable (e.g. the gateway
    endpoint isn't deployed yet, or no creds) — callers fall back gracefully."""
    ak = os.environ.get("OBSIDEO_S3_ACCESS_KEY")
    sk = os.environ.get("OBSIDEO_S3_SECRET_KEY")
    if not (ak and sk):
        return None
    try:
        from botocore.auth import SigV4Auth
        from botocore.awsrequest import AWSRequest
        from botocore.credentials import Credentials
        endpoint = os.environ.get("OBSIDEO_S3_ENDPOINT", "https://s3.obsideo.io").rstrip("/")
        region = os.environ.get("OBSIDEO_S3_REGION", "us-east-1")
        url = f"{endpoint}/v1/account"
        signed = AWSRequest(method="GET", url=url)
        SigV4Auth(Credentials(ak, sk), "s3", region).add_auth(signed)
        req = urllib.request.Request(url, headers=dict(signed.headers), method="GET")
        with urllib.request.urlopen(req, timeout=15, context=config.ssl_context()) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return None


def main():
    argv = sys.argv[1:]

    # Version (stdout, clean + parseable — handled before any chrome).
    if argv and argv[0] in ("--version", "-V", "version"):
        print(f"obsideo-cli {config.VERSION}")
        return

    # Branded banner on every init (stderr, TTY-gated). Skip for `admin` so
    # operator tooling output stays clean.
    if not (argv and argv[0] == "admin"):
        show_banner()

    # Standard --help / -h (cmd.Cmd would otherwise read "--help" as a command).
    if argv and argv[0] in ("-h", "--help", "help"):
        ObsideoShell().onecmd("help")
        return

    # `obsideo login` is handled specially: it is the one command that may
    # prompt, and the one an agent most needs to drive without prompting.
    if argv and argv[0] == "login":
        opts, err = _parse_login_args(argv[1:])
        if err:
            print(err)
            print(LOGIN_USAGE)
            sys.exit(2)
        if opts.pop("help", False):
            print(LOGIN_USAGE)
            sys.exit(0)
        ok = run_login(**opts)
        if ok and not opts.get("json_out"):
            show_status()
        sys.exit(0 if ok else 1)

    # `obsideo admin ...` is operator tooling, not a shell command.
    if argv and argv[0] == "admin":
        sys.exit(run_admin(argv[1:]))

    # Surface any pending operator broadcasts (no-op unless interactive).
    show_notices()

    shell = ObsideoShell()

    # One-shot: `obsideo ls`, `obsideo put file.txt`, etc. No update prompt or
    # status line here — one-shots stay fast and scriptable.
    if argv:
        shell.onecmd(" ".join(argv))
        return

    # Interactive session ("initialization"): offer an update if one's out.
    check_for_update()

    # First-run nudge: not logged in -> offer login.
    if not config.is_logged_in():
        print("Welcome to Obsideo - your content is encrypted before it leaves your machine.")
        if input("Log in / sign up now? (Y/n): ").strip().lower() in ("", "y", "yes"):
            if not run_login():
                return
        else:
            print("Run 'obsideo login' when you're ready.")
            return

    show_status()
    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        print("\nadios amigo")


if __name__ == "__main__":
    main()
