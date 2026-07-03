"""Map a shell command to capabilities against a shell-normalised form.

A raw ``\\bcurl\\b`` regex is trivially evaded — ``c""url``, ``FOO=1 curl``,
``/usr/bin/curl``, ``sudo curl``, ``C=curl; $C`` all run curl while dodging the
match. So the command is tokenised like a shell would (:mod:`shlex`), split into
simple commands, stripped of env-assignment prefixes and wrappers
(``sudo``/``env``/``timeout`` …), and ``VAR=val`` indirection is resolved; rules
run against that normal form.

Not a sandbox: command substitution is Turing-complete, so this raises the bar
from "fooled by quotes" to "needs real obfuscation" and flags dynamic constructs
(``$(…)``, ``eval``, ``base64 -d``) for conservative handling. Fail-safe: a parse
failure returns ``None`` so the caller treats the command as an opaque exec.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from typing import List, Optional

from certior_guard.patterns import SECRET_INLINE, SECRET_PATH

# Commands that delegate to a command given in their arguments — peel them off
# so ``sudo curl`` / ``timeout 5 curl`` / ``xargs curl`` resolve to ``curl``.
_WRAPPERS = {
    "sudo", "doas", "command", "env", "nohup", "nice", "ionice", "stdbuf",
    "setsid", "time", "timeout", "watch", "xargs", "exec", "builtin",
    "caffeinate", "chrt",
}
# Tokens that separate simple commands. Redirections (``>`` ``>>`` ``<``) are
# handled separately so their targets can be inspected; ``|`` is also tracked
# as a pipe for the fetch-and-run-into-a-shell rule.
_OPERATORS = {"|", "||", "&&", ";", "&", "|&", "(", ")"}
_PIPES = {"|", "|&"}

_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "ash", "fish", "csh", "tcsh", "busybox"}
_DOWNLOADERS = {"curl", "wget", "fetch", "aria2c", "lynx", "w3m", "httpie", "http"}

_ASSIGN = re.compile(r"^[A-Za-z_]\w*=")
_VARREF = re.compile(r"^\$\{?([A-Za-z_]\w*)\}?$")
_DYNAMIC = re.compile(r"\$\(|`|\beval\b|\bsource\b|base64\s+-{0,2}d|\bxxd\b\s+-r|\bopenssl\b.*\benc\b.*-d")


@dataclass
class SimpleCommand:
    """One command in a pipeline/list, normalised to its bare executable."""
    executable: str          # basename, quotes removed, wrappers/assignments peeled
    args: List[str] = field(default_factory=list)

    @property
    def exe(self) -> str:
        return self.executable.lower()


@dataclass
class ParsedShell:
    commands: List[SimpleCommand]
    piped: bool              # the command line contains a pipe
    has_dynamic: bool        # command substitution / eval / base64-decode present
    redirect_targets: List[str] = field(default_factory=list)


def _basename(token: str) -> str:
    return token.rsplit("/", 1)[-1]


def _tokenize(command: str) -> Optional[List[str]]:
    """Shell-tokenise ``command`` (quote/escape removal, operators split out).

    Returns ``None`` on a parse error (e.g. unbalanced quotes) so the caller
    falls back to the legacy regex path rather than guessing.
    """
    # Treat newlines as command separators (shlex would swallow them as plain
    # whitespace and silently merge two commands into one).
    command = command.replace("\n", " ; ").replace("\r", " ")
    lex = shlex.shlex(command, posix=True, punctuation_chars=";&|<>()")
    lex.whitespace_split = True
    try:
        return list(lex)
    except ValueError:
        return None


def _substitute_vars(tokens: List[str]) -> List[str]:
    """Resolve simple ``VAR=val`` … ``$VAR`` indirection within one command line.

    Loose by design (ignores scope/ordering) — for a guard, resolving
    ``C=curl; $C`` to ``curl`` and erring toward caution is the right trade.
    """
    varmap = {}
    for t in tokens:
        if _ASSIGN.match(t):
            name, _, val = t.partition("=")
            varmap[name] = val
    if not varmap:
        return tokens
    out = []
    for t in tokens:
        m = _VARREF.match(t)
        if m and m.group(1) in varmap:
            out.append(varmap[m.group(1)])
        else:
            out.append(t)
    return out


def _peel(tokens: List[str]) -> Optional[SimpleCommand]:
    """Drop leading assignments and wrapper commands; return the real command."""
    i, n = 0, len(tokens)
    while i < n:
        t = tokens[i]
        if _ASSIGN.match(t):            # FOO=bar env-assignment prefix
            i += 1
            continue
        base = _basename(t)
        if base.lower() in _WRAPPERS:   # sudo / env / timeout 5 / xargs -I{} …
            i += 1
            while i < n and (tokens[i].startswith("-") or tokens[i].isdigit()):
                i += 1
            continue
        # Only the executable is reduced to a basename; arguments keep their
        # full text because paths matter (e.g. secret-file detection).
        return SimpleCommand(executable=base, args=list(tokens[i + 1:]))
    return None


def analyze(command: str) -> Optional[ParsedShell]:
    """Parse ``command`` into normalised simple commands, or ``None`` on failure."""
    if not command or not command.strip():
        return ParsedShell(commands=[], piped=False, has_dynamic=False)
    tokens = _tokenize(command)
    if tokens is None:
        return None
    tokens = _substitute_vars(tokens)

    piped = any(t in _PIPES for t in tokens)
    redirect_targets: List[str] = []
    commands: List[SimpleCommand] = []
    segment: List[str] = []
    expect_redirect_target = False
    for t in tokens:
        if expect_redirect_target:
            redirect_targets.append(t)
            expect_redirect_target = False
            continue
        if t in (">", ">>", "<", ">|"):
            expect_redirect_target = True
            continue
        if t in _OPERATORS:
            if segment:
                cmd = _peel(segment)
                if cmd:
                    commands.append(cmd)
                segment = []
            continue
        segment.append(t)
    if segment:
        cmd = _peel(segment)
        if cmd:
            commands.append(cmd)

    return ParsedShell(
        commands=commands,
        piped=piped,
        has_dynamic=bool(_DYNAMIC.search(command)),
        redirect_targets=redirect_targets,
    )


_READERS = {"cat", "less", "more", "head", "tail", "grep", "egrep", "strings",
            "xxd", "od", "base64", "bat", "nl", "tac", "awk", "sed", "cut"}
# Interpreters that run inline code (``python -c`` / ``node -e``) — a common way
# to read a secret file without naming a recognised reader command.
_INTERPRETERS = {"python", "python2", "python3", "node", "nodejs", "deno", "bun",
                 "ruby", "perl", "php", "rscript"}
# Commands that duplicate a file's contents; copying a secret out is a read.
_COPIERS = {"cp", "mv", "install", "ln"}
_DESTROYERS = {"dd", "shred", "wipefs", "blkdiscard"}
_DEPLOYERS = {"kubectl", "terraform", "helm", "serverless", "vercel", "netlify",
              "fly", "flyctl", "pulumi", "ansible-playbook", "aws"}
_DEPLOY_VERBS = {"apply", "deploy", "destroy", "delete", "up", "provision"}
# Package managers whose install/add pulls third-party code — a supply-chain surface.
_INSTALLERS = {"npm", "pnpm", "yarn", "pip", "pip3", "pipx", "uv", "poetry",
               "gem", "bundle", "cargo", "go", "apt", "apt-get", "brew", "apk"}
_INSTALL_VERBS = {"install", "add"}
_DB_DANGER = re.compile(r"\bdrop\b|\btruncate\b|\bdelete\s+from\b", re.IGNORECASE)


def _is_install(exe: str, args: List[str]) -> bool:
    if exe not in _INSTALLERS:
        return False
    if any(a in _INSTALL_VERBS for a in args):
        return True
    return (exe == "npm" and args[:1] == ["i"]) or (exe == "go" and "get" in args)


def shell_capabilities(command: str) -> Optional[List[str]]:
    """Map a Bash command to capability candidates via the parsed normal form.

    Returns a (possibly empty) list of capability strings, or ``None`` if the
    command could not be parsed — signalling the caller to fall back to the
    legacy regex rules. An empty list means "nothing dangerous matched".
    """
    parsed = analyze(command)
    if parsed is None:
        return None

    caps: List[str] = []

    def add(*cs: str) -> None:
        for c in cs:
            if c not in caps:
                caps.append(c)

    has_downloader = any(c.exe in _DOWNLOADERS for c in parsed.commands)
    has_shell = any(c.exe in _SHELLS for c in parsed.commands)

    # curl|wget … | sh  →  fetch-and-run remote code.
    if has_downloader and has_shell and parsed.piped:
        add("code:exec", "remote:exfiltrate")
    # bash -c "$(curl …)" / eval $(curl …) — dynamic fetch into a shell.
    if parsed.has_dynamic and (has_shell or any(c.exe == "eval" for c in parsed.commands)):
        if has_downloader or re.search(r"curl|wget", command, re.IGNORECASE):
            add("code:exec", "remote:exfiltrate")

    for c in parsed.commands:
        exe, args = c.exe, c.args

        if exe in _DESTROYERS or exe.startswith("mkfs"):
            add("fs:destroy")
        elif exe == "rm" and any(f.startswith("-") and ("r" in f or "f" in f) for f in args):
            add("fs:delete")
        elif exe == "git" and args[:1] == ["push"]:
            add("git:push")
        elif exe == "git" and args[:1] == ["merge"]:
            add("git:merge")
        elif exe in _DEPLOYERS and any(a in _DEPLOY_VERBS for a in args):
            add("prod:deploy")
        elif exe == "docker" and "push" in args:
            add("prod:deploy")
        elif exe in ("npm", "pnpm", "yarn") and "publish" in args:
            add("package:publish")
        elif exe == "twine" and "upload" in args:
            add("package:publish")
        elif exe == "cargo" and "publish" in args:
            add("package:publish")
        elif exe in ("psql", "mysql", "mongo", "mongosh") and _DB_DANGER.search(" ".join(args)):
            add("db:destroy")
        elif _is_install(exe, args):
            add("deps:install")
        elif exe in _READERS and any(SECRET_PATH.search(a) for a in args):
            add("secrets:read")
        elif exe in _INTERPRETERS and any(SECRET_INLINE.search(a) for a in args):
            # python -c "open('.env')" / node -e "readFileSync('.env')" / perl -pe 1 .env
            add("secrets:read")
        elif exe in ("source", ".") and any(SECRET_PATH.search(a) for a in args):
            # `source .env` / `. ./.env` — loads a secret file into the environment
            add("secrets:read")
        elif exe in _COPIERS and any(
            SECRET_PATH.search(a) for a in args[:-1] if not a.startswith("-")
        ):
            # `cp .env /tmp/x` — reads a secret out under a new (non-secret) name
            add("secrets:read")
        elif exe in ("scp", "rsync") and any("@" in a for a in args):
            add("data:exfiltrate")
        elif exe in _DOWNLOADERS and any(
            a in ("-F", "-d", "--data", "--data-binary", "-T", "--upload-file") for a in args
        ) and any(re.match(r"https?://(?!localhost|127\.)", a) for a in args):
            add("data:exfiltrate")

    # Writing to a raw block device wipes a disk regardless of the tool used.
    if any(re.match(r"/dev/(sd|nvme|mmcblk|vd|hd)", t) for t in parsed.redirect_targets):
        add("fs:destroy")

    return caps
