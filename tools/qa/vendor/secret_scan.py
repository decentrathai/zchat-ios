#!/usr/bin/env python3
"""ZCHAT secret scanner that never prints a secret (versioned home of the 24 Sep sweep scanner).

One line per hit on stdout:  <where>:<line>\t<kind>\t<hard|soft>
No value, no prefix of a value and no length is ever printed. A known secret value (from
~/.claude/.secrets, ~/.zchat-parked/device-pins.env, ~/.config/zchat-qa/pins.json) is matched in memory
and reported only by its variable NAME, always with line 0: a pointer to the digits a short PIN collides
with would reveal the PIN.

HARD hits block (exit 1); SOFT hits are reported and never block (exit 0):
  hard  tokens (GitHub, Telegram, sk-, AWS), Zcash spending/viewing keys, nsec, WIF, PEM private-key
        blocks, secret files by name (.env, *.p12, *.pem, *.mnemonic, *.seed, *.dpapi, secrets*, ...),
        long known values, a short known value standing alone next to a PIN word, a checksum-valid BIP39
        phrase that is not a public vector, URL credentials that are not a placeholder, and outside test
        fixture paths: quoted password/secret literals, secret-named 64-hex values, full Zcash addresses.
  soft  `password: String`-style code shapes, literals and addresses inside test fixture paths, short or
        numeric known values that merely collide with other digits, BIP39-word runs without a valid phrase.
        Also (ZC-701, kind checksum-digest) the digest lines of a checksum file: a 64-hex value at the start of
        its line, alone or followed by a file name, in a file that is a checksum file by its NAME (SHA256SUMS,
        EXPECTED-SHA256SUMS, sha256sums.txt, CHECKSUMS ...): the file scanned or, inside a unified diff, the
        file the hunk belongs to. They are counted so that they stay visible. The name decides, never the shape
        of the line alone: the same lines in a file of another name are judged as before.
  none  a 64-hex value where a file digest is printed (sha256sum and MANIFEST lines, APK hash lines, a SHA-256
        table column, a Blossom/NIP-96 file URL and its NIP-94 x/ox tags, block hashes) unless a secret word comes
        before it on its line, and a secret-named URL constant whose URL carries no key (ZC-313). Also (ZC-408): a
        MANIFEST row with a size column, a mapping keyed by a hash whose label names the MANIFEST, a report bullet
        under a heading that names APKs or digests, a key=value line whose key ends in apk, a JSON array of
        digests under a key that names a digest, and a `*.sha256` file that holds nothing but one digest.

Usage:
  secret_scan.py [opts] files <path>...           walk files (skips .git, build, node_modules, ...)
  secret_scan.py [opts] git <repo> [<rev-range>]  added lines of git history (default: all refs)
  secret_scan.py [opts] tree <repo> <rev>         every file of the tree at <rev>
  secret_scan.py [opts] staged [<repo>]           added lines of the staged diff (pre-commit)
  secret_scan.py [opts] --staged                  same, repo = current directory
  secret_scan.py [opts] stdin <label>             text on stdin
Options:
  --summary     print counts by kind and severity only (no paths)
  --hard-only   print only hard hits
  --allow FILE  allow list (default tools/qa/secret_scan.allow.txt; env SECRET_SCAN_ALLOW)
  --no-known    skip known-value matching (env SCAN_NO_KNOWN=1 does the same)
Env: SECRET_SCAN_KNOWN_FILES=<file>[:<file>...] replaces the default known-value files.
Exit: 0 clean or soft only, 1 at least one hard hit, 2 usage or setup error.
"""
from __future__ import annotations

import base64
import collections
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
WORDLIST_PATH = HERE / "bip39_english.txt"
WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"  # official BIP39 english
DEFAULT_ALLOW = HERE / "secret_scan.allow.txt"
KNOWN_FILES = (Path.home() / ".claude" / ".secrets", Path.home() / ".zchat-parked" / "device-pins.env")
MAX_BYTES = 5_000_000

SKIP_DIRS = {".git", "node_modules", "build", ".gradle", ".idea", "__pycache__", ".venv", "venv", ".next",
             "dist", ".cache", ".kotlin", ".cxx"}
BINARY_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".apk", ".aab", ".so", ".jar", ".class", ".dex", ".zip",
              ".gz", ".tgz", ".tar", ".pdf", ".mp4", ".ttf", ".otf", ".woff", ".woff2", ".ico", ".bin", ".db",
              ".sqlite", ".keystore", ".jks", ".p12", ".webm", ".mp3", ".ogg", ".wav"}
SECRET_FILE = re.compile(r"(?i)(\.jks|\.keystore|\.p12|\.pfx|\.pem|\.mnemonic|\.seed|\.dpapi|\.env)$"
                         r"|(^|/)(id_rsa|id_ed25519|id_ecdsa|\.env|secrets[^/]*)$")
FIXTURE_PATH = re.compile(r"(^|/)(src/test|src/androidTest|src/testFixtures|tools/qa/tests|fixtures?|testdata)(/|$)")
FAKE_MARKER = "secret-scan: fake"


# ---------------------------------------------------------------------------------------------------------
# BIP39

def load_wordlist(path: Path | str = WORDLIST_PATH) -> list[str]:
    """The official english list, or ValueError: a missing or altered list must not silently turn the phrase
    check off."""
    raw = Path(path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != WORDLIST_SHA256:
        raise ValueError(f"{path}: not the official BIP39 english word list")
    return [w.strip() for w in raw.decode().splitlines() if w.strip()]


WORDS = load_wordlist()
IDX = {w: i for i, w in enumerate(WORDS)}


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def bip39_valid(words: list[str]) -> bool:
    n = len(words)
    if n not in (12, 15, 18, 21, 24) or any(w not in IDX for w in words):
        return False
    bits = "".join(format(IDX[w], "011b") for w in words)
    cs = n // 3
    ent = int(bits[:-cs], 2).to_bytes((len(bits) - cs) // 8, "big")
    return format(hashlib.sha256(ent).digest()[0], "08b")[:cs] == bits[-cs:]


def _phrase(ent: bytes) -> list[str]:
    bits = "".join(format(b, "08b") for b in ent)
    cs = len(ent) * 8 // 32
    bits += format(hashlib.sha256(ent).digest()[0], "08b")[:cs]
    return [WORDS[int(bits[i:i + 11], 2)] for i in range(0, len(bits), 11)]


# Public BIP39 reference vectors (python-mnemonic / Trezor vectors.json entropies), recomputed at load.
PUBLIC_PHRASES = frozenset(fingerprint(" ".join(_phrase(bytes([b]) * n)))
                           for b in (0x00, 0x7F, 0x80, 0xFF) for n in (16, 20, 24, 28, 32))


# ---------------------------------------------------------------------------------------------------------
# bech32 / bech32m / base58check

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32, BECH32M = 1, 2
_CONST = {BECH32: 1, BECH32M: 0x2BC830A3}
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _polymod(values) -> int:
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if (top >> i) & 1 else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def bech32_verify(s: str) -> int | None:
    if s.lower() != s and s.upper() != s:
        return None
    s = s.lower()
    pos = s.rfind("1")
    if pos < 1 or pos + 7 > len(s):
        return None
    hrp, data = s[:pos], s[pos + 1:]
    if any(c not in CHARSET for c in data):
        return None
    const = _polymod(_hrp_expand(hrp) + [CHARSET.find(c) for c in data])
    for spec, c in _CONST.items():
        if const == c:
            return spec
    return None


def bech32_encode(hrp: str, data: list[int], spec: int) -> str:
    values = _hrp_expand(hrp) + list(data)
    mod = _polymod(values + [0] * 6) ^ _CONST[spec]
    return hrp + "1" + "".join(CHARSET[d] for d in list(data) + [(mod >> 5 * (5 - i)) & 31 for i in range(6)])


def b58check_decode(s: str) -> bytes | None:
    n = 0
    for c in s:
        i = B58.find(c)
        if i < 0:
            return None
        n = n * 58 + i
    raw = b"\x00" * (len(s) - len(s.lstrip("1"))) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    if len(raw) < 5:
        return None
    body, chk = raw[:-4], raw[-4:]
    return body if hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] == chk else None


# ---------------------------------------------------------------------------------------------------------
# Allow list: "<kind> sha256:<64 hex> <why>" for a public value, "history <commit>:<path>:<kind> <why>"
# for a reviewed hit in git history. Hashes only, never values. Known values can never be allowed, with one
# exception (ZC-2063): "public-id <NAME> sha256:<64 hex> <why>" for a known value whose NAME this scanner declares
# public below. It lifts that NAME's known-value hit and the shape hits of that exact value; the same value under any
# other NAME, and every other value, still hits.

#: Known-value names that hold a public identifier, never a secret. Only these may have a public-id line.
#: NEAR_SWAP_FEE_ACCOUNT: the NEAR implicit account (64 hex) that receives the swap app fee; every swap names it in
#: public to 1Click as the appFees recipient, and gradle.properties carries it for store builds (ZC-2058, W-167.3).
#: Its signing key (NEAR_SWAP_FEE_SECRET_KEY) is a secret and is never on this list.
PUBLIC_KNOWN_NAMES = frozenset({"NEAR_SWAP_FEE_ACCOUNT"})


@dataclass
class Allow:
    entries: list[tuple[str, str, str]] = field(default_factory=list)
    history: list[tuple[str, str, str, str]] = field(default_factory=list)
    public_ids: list[tuple[str, str, str]] = field(default_factory=list)  # (NAME, sha256, why)

    @classmethod
    def parse(cls, text: str) -> "Allow":
        a = cls()
        for n, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.split(None, 1)[0] == "public-id":
                m = re.fullmatch(r"public-id\s+([A-Za-z0-9_]+)\s+sha256:([0-9a-f]{64})\s+(.+)", line)
                if not m:
                    raise ValueError(f"allow list line {n}: expected 'public-id <NAME> sha256:<64 hex> <why>'")
                if m.group(1) not in PUBLIC_KNOWN_NAMES:
                    raise ValueError(f"allow list line {n}: {m.group(1)} is not a public known-value name "
                                     f"(secret_scan.PUBLIC_KNOWN_NAMES)")
                a.public_ids.append(m.groups())
                continue
            m = re.fullmatch(r"(\S+)\s+sha256:([0-9a-f]{64})\s+(.+)", line)
            if m and m.group(1) != "history":
                a.entries.append((m.group(1), m.group(2), m.group(3)))
                continue
            m = re.fullmatch(r"history\s+([0-9a-f]{7,40}):(\S+):(\S+)\s+(.+)", line)
            if m:
                a.history.append(m.groups())
                continue
            raise ValueError(f"allow list line {n}: expected '<kind> sha256:<64 hex> <why>' "
                             "or 'history <commit>:<path>:<kind> <why>'")
        return a

    def allows(self, kind: str, value: str) -> bool:
        fp = fingerprint(value)
        return any(k == kind and h == fp for k, h, _ in self.entries) or self.public_value(value)

    def public_value(self, value: str) -> bool:
        """The value is a declared public identifier (any public-id line): its shape hits are lifted."""
        fp = fingerprint(value)
        return any(h == fp for _n, h, _w in self.public_ids)

    def public_known(self, name: str, value: str) -> bool:
        """The known value `name`=`value` is declared public: a public-id line for this NAME and this value."""
        if name not in PUBLIC_KNOWN_NAMES:
            return False
        fp = fingerprint(value)
        return any(n == name and h == fp for n, h, _w in self.public_ids)

    def allows_history(self, commit: str, path: str, kind: str) -> bool:
        return any((commit.startswith(c) or c.startswith(commit)) and p == path and k == kind
                   for c, p, k, _ in self.history)


def load_allow(path: Path | str | None = None) -> Allow:
    path = path or os.environ.get("SECRET_SCAN_ALLOW") or DEFAULT_ALLOW
    try:
        return Allow.parse(Path(path).read_text())
    except FileNotFoundError:
        return Allow()


# ---------------------------------------------------------------------------------------------------------
# Known values

_ENV_LINE = re.compile(r"""\s*(?:export\s+)?([A-Za-z0-9_]+)\s*=\s*["']?([^"'\n#]+)""")
SOFT_KNOWN_NAMES = {"X_ACCOUNT_USERNAME"}  # an identity, not a secret
PIN_CONTEXT = re.compile(r"(?i)\b(pins?|passcodes?|unlock|password|passwd|lock ?screen|seed ?vault|destroy)\b")


def load_known(paths=None) -> dict[str, list[str]]:
    """NAME -> values. Hosts, users, ids and `$` references are not secrets; values under 4 characters would
    match everywhere; a *_CANDIDATES list is split on spaces."""
    out: dict[str, list[str]] = {}
    for p in paths if paths is not None else KNOWN_FILES:
        try:
            lines = Path(p).read_text().splitlines()
        except OSError:
            continue
        for line in lines:
            m = _ENV_LINE.match(line)
            if not m:
                continue
            name, val = m.group(1), m.group(2).strip()
            if name == "PATH" or name.upper().endswith(("_HOST", "_USER", "_ID")) or "$" in val:
                continue
            vals = val.split() if name.upper().endswith("_CANDIDATES") else [val]
            vals = [v for v in vals if len(v) >= 4]
            if vals:
                out.setdefault(name, []).extend(v for v in vals if v not in out.get(name, []))
    return out


def _known_pins() -> dict[str, list[str]]:
    cfg = Path(os.environ.get("ZQA_CONFIG_DIR", Path.home() / ".config" / "zchat-qa")).expanduser()
    try:
        pins = json.loads((cfg / "pins.json").read_text())
    except (OSError, ValueError):
        return {}
    out = {}
    if isinstance(pins, dict):
        for i, pin in enumerate(pins.values(), start=1):
            if isinstance(pin, (str, int)) and len(str(pin)) >= 4:
                out[f"pins.json#{i}"] = [str(pin)]
    return out


def default_known() -> dict[str, list[str]]:
    if os.environ.get("SCAN_NO_KNOWN") or os.environ.get("ZQA_NO_KNOWN_VALUES"):
        return {}
    override = os.environ.get("SECRET_SCAN_KNOWN_FILES")
    if override is not None:
        return load_known([p for p in override.split(os.pathsep) if p])
    return {**load_known(), **_known_pins()}


def known_severity(name: str, value: str) -> str:
    """Numeric or short values collide with ordinary digits and words: report-only unless they stand alone
    next to a PIN word (see _known_hits)."""
    if name in SOFT_KNOWN_NAMES or value.isdigit() or len(value) < 8:
        return "soft"
    return "hard"


# ---------------------------------------------------------------------------------------------------------
# Shapes

_BECH_CH = "[" + CHARSET + "]"
REGEX_HARD: tuple[tuple[str, re.Pattern], ...] = (
    ("zcash-spending-key", re.compile(r"secret-extended-key-(?:main|test)1[0-9a-z]{20,}")),
    ("zcash-spending-key", re.compile(r"(?<![0-9a-z])(?:zxsk|zsk)1[0-9a-z]{20,}")),
    # unified and Sapling viewing keys of both networks; uvf/uvi are the ZIP 316 revision 2 forms (ZC-714)
    ("zcash-viewing-key", re.compile(r"(?<![0-9a-z])(?:uview|uivk|zxviews|uviewtest|uivktest|zxviewtestsapling|"
                                     r"uvf|uvi|uvftest|uvitest)1[0-9a-z]{50,}")),
    ("nostr-secret-key", re.compile(r"(?<![0-9a-z])nsec1" + _BECH_CH + r"{50,}")),
    ("github-token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|\bgithub_pat_[A-Za-z0-9_]{40,}")),
    ("telegram-bot-token", re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{30,}")),
    ("api-key", re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{24,}")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
)
_PEM = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")
_WIF = re.compile(r"(?<![0-9A-Za-z])[KL5][1-9A-HJ-NP-Za-km-z]{50,51}(?![0-9A-Za-z])")
_URL_CRED = re.compile(r"[a-z][a-z0-9+.-]*://([^\s/:@]+):([^\s/@]{4,})@[^\s/]+")
_URL_PLACEHOLDER = re.compile(r"(?i)^(\$\{?\w+\}?|<[^>]+>|%\w+%?|\*+|x{3,}|\.{3}|…|password|pass|secret|changeme|"
                              r"your[_-]?\w*|token)$")
_PASSWORD_SHAPE = re.compile(r"(?i)\b(?:password|passwd|passphrase|pass|pwd|keystore_password|key_password|"
                             r"store_password)\b\s*[:=]\s*[\"']?[^\s\"'<>{}$]{6,}")
_PASSWORD_QUOTED = re.compile(r"(?i)(?:pass(?:word|wd|phrase)|pwd)\w*[\"']?\s*[:=]\s*([\"'])([^\"'\s$<>{}]{6,})\1")
_PASSWORD_BARE = re.compile(r"(?i)(?:pass(?:word|wd|phrase)|pwd)\w*\s*[:=]\s*([^\s\"'<>{}$()]{6,})\s*$")
_CONFIG_EXT = (".properties", ".env", ".yml", ".yaml", ".ini", ".conf", ".cfg", ".toml")
_APIKEY_SHAPE = re.compile(r"(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|bot[_-]?token|"
                           r"client[_-]?secret)\b\s*[:=]\s*([\"']?)([A-Za-z0-9_\-.]{16,})")
_NAMED_LITERAL = re.compile(r"(?<![\w$])([A-Za-z_][\w]*)[\"']?(?:\s*:\s*[A-Za-z_][\w.<>?]*)?\s*[:=]\s*([\"'])"
                            r"([^\"'\s$]{16,})\2")
_SECRET_NAME = re.compile(r"(?i)secret|token|api_?key|private_?key")
_HEX64 = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{64}(?![0-9A-Za-z])")
_SECRET_WORDS = re.compile(r"(?i)(_priv|priv_?key|private_?key|\bpriv\b|sec_?key|secret|seed|nsec|mnemonic|"
                           r"spending|signing|passw)")
_PUBLIC_WORDS = re.compile(
    r"(?i)(sha-?\d*|digest|hash|checksum|tx_?id|txn|transaction|pub_?key|public[_ ]?key|npub|commit|merkle|"
    r"anchor|nullifier|cmx|cmu|event_?id|block|vector|expected|fixture|integrity|fingerprint|cert|\bid\b|_id\b|"
    r"\bapks?\b|(?-i:[a-z]Id\b))")
# a value labelled as a digest right before it (`sha256:<hex>`, `SHA-256 = <hex>`, `| Signing cert SHA-256 | `<hex>`)
# is a digest even when a secret word comes earlier on the line (output_scan's _HASH_LABEL; ZC-313)
_HASH_LABEL = re.compile(r"(?i)(?:sha-?\d*(?:sum)?|digest|hash|checksum)[\"'`*]*\s*[:=|]?\s*[\"'`]?$")
# Full addresses of both networks (ZC-714: the testnet forms were unknown, so a full utest1, ztestsapling1, textest1
# or testnet transparent address passed every scan). Human-readable part -> (checksum, least length of the whole
# string): unified, Sapling and TEX of mainnet and testnet, and the unified addresses of ZIP 316 revision 2 (zu, tu:
# Bech32m like revision 0). The names and the transparent version bytes below are librustzcash's
# (zcash_protocol/src/constants/mainnet.rs and testnet.rs).
ADDRESS_SPECS = {"u": (BECH32M, 100), "zs": (BECH32, 75), "tex": (BECH32M, 38),
                 "utest": (BECH32M, 100), "ztestsapling": (BECH32, 75), "textest": (BECH32M, 38),
                 "zu": (BECH32M, 60), "tu": (BECH32M, 60), "zutest": (BECH32M, 60), "tutest": (BECH32M, 60)}
_BECH_ADDR = re.compile(r"(?<![0-9a-z])(" + "|".join(sorted(ADDRESS_SPECS, key=len, reverse=True)) + ")1"
                        + _BECH_CH + r"{30,}")
# transparent: t1, t3 (mainnet P2PKH, P2SH), tm, t2 (testnet)
_T_ADDR = re.compile(r"(?<![0-9A-Za-z])t[123m][1-9A-HJ-NP-Za-km-z]{33,34}(?![0-9A-Za-z])")
T_ADDR_VERSIONS = (b"\x1c\xb8", b"\x1c\xbd", b"\x1d\x25", b"\x1c\xba")
_CONCAT = re.compile(r"([\"'])\s*\+\s*([\"'])")
_WORD = re.compile(r"[A-Za-z]+")
_PHRASE_GAP = re.compile(r"""[ \t\r\n"'`,+.\d():\[\]\\-]*""")

# ---------------------------------------------------------------------------------------------------------
# Digest contexts (ZC-313): where a 64-hex value is a file digest, not a secret. They count only when no secret
# word comes before the value on its line. The first five mirror tools/qa/hooks/output_scan.py (ZC-241, ZC-254).

# sha256sum's own output, `<hex>  <file>` / `<hex> *<file>`
_SHASUM_LINE = re.compile(r"^\\?[0-9a-fA-F]{64} [ *]\S")
# the same lines indented, bulleted or behind a grep `file:` / `file:NN:` prefix (the prefix holds a `.` or `/`), when
# a PATH follows the digest (a `/` or a letter extension)
_GREP_PREFIX = r"(?:[^\s:|`]*[./][^\s:|`]*:(?:\d+[:-])?)?"
_SUM_BEFORE = re.compile(r"^" + _GREP_PREFIX + r"[ \t]*(?:[-*+>][ \t]+)?\\?$")
_SUM_AFTER = re.compile(r"^(?: [ *]|\t)\S*(?:/\S|\.[A-Za-z][A-Za-z0-9]*\b)")
# path-first MANIFEST rows of a build artifact (`app-release.apk  <hex>`, `| x.aab | `<hex>` |`)
_ARTIFACT_BEFORE = re.compile(
    r"(?i)^" + _GREP_PREFIX + r"[ \t|>*+-]*\S*\.(?:apk|aab|apks|aar|jar|so|zip|tar|gz|tgz|xz|zst|bin|img|patch|diff|bundle)"
    r"[ \t|:=]*`?$")
_ARTIFACT_AFTER = re.compile(r"^`?(?:\s|\||$)")
# an APK hash in a build or phone report: "<slot> `<hex>` (<package id>, <versionCode>)"
_APK_ID_AFTER = re.compile(r"^`?\s*\(\s*xyz\.zsend\.zchat[\w.]*\s*,\s*\d{3,6}\s*\)")
# a block hash in display order starts with 8+ zero hex digits
_BLOCK_HASH_ZEROS = "0" * 8
# a markdown table column whose header names a digest (`| APK | Package | Signer | SHA-256 |`)
_TABLE_RULE = re.compile(r"^\s*\|?\s*:?-{3,}:?\s*(?:\|\s*:?-{3,}:?\s*)*\|?\s*$")
_DIGEST_NAME = re.compile(r"(?i)sha-?\d*|hash|digest|checksum|fingerprint|integrity|\bmd5\b|\bblake")
# the APK hash an install log prints on a line of its own under the package block: the app's package id and a
# versionCode within the 4 lines above, no blank line between
_BARE_HEX_LINE = re.compile(r"^\s*`?[0-9a-fA-F]{64}`?\s*$")
_APP_PACKAGE = re.compile(r"\bxyz\.zsend\.zchat[\w.]*")
_VERSION_CODE = re.compile(r"\bversionCode\s*[=:]\s*\d{3,6}\b")
# a Blossom / NIP-96 file URL names the blob by its SHA-256: the PATH of a URL on a file host the app uploads to (keep
# in sync with ZFILEMessage.ALLOWED_MEDIA_HOSTS; a subdomain counts, as there), never its query or fragment
FILE_HOSTS = ("nostr.download", "blossom.yakihonne.com", "cdn.hzrd149.com", "files.sovbit.host", "blossom.primal.net",
              "blossom.band", "blossom.nostr.build", "nostr.build")
_URL_PATH = re.compile(r"(?i)https?://([a-z0-9.-]+)(?::\d+)?(/[^\s\"'`<>()\[\]{}?#]*)")
# the NIP-94 file-metadata tags that hold a SHA-256 by definition: ["x", "<hex>"] and ["ox", "<hex>"]
_NIP94_TAG_BEFORE = re.compile(r"""\[\s*["']o?x["']\s*,\s*["']$""")
_NIP94_TAG_AFTER = re.compile(r"""^["']\s*\]""")
# ZC-408: four more places, each narrow (the near misses stay hard hits; tests MoreDigestShapes).
# a bundle MANIFEST row with a size column, `<hex>     7954  CTX_schema.prisma.txt` (the sha256sum rule needs the name
# right after the digest): the digest first, then a decimal byte count, then one PATH to the end of the line
_SIZED_ROW_AFTER = re.compile(r"^[ \t]+\d{1,12}[ \t]+\S*(?:/\S|\.[A-Za-z][A-Za-z0-9]*\b)\S*[ \t]*$")
# a mapping keyed by an APK hash whose label names the MANIFEST it was read from:
# `{"<hex>": "T4c 3df251d7f (MANIFEST debug)"`; the hex is the quoted KEY, the value a quoted label without a secret word
_MAP_LABEL_AFTER = re.compile(r"""^\s*:\s*(["'])((?:(?!\1).)*)\1""")
_MANIFEST_WORD = re.compile(r"(?i)\bmanifest\b")
# a report bullet with a label, `- Debug: `<hex>` (debug signer …)`, under a heading that names APKs or digests; only
# list items, their indented continuation lines and blank lines may stand between the heading and the bullet
_LABELLED_ITEM_BEFORE = re.compile(r"^\s*[-*+]\s+[^:`|=]{1,40}:\s*`?$")
_ITEM_AFTER = re.compile(r"^`?(?:[\s(,;.]|$)")
_TX_LABEL = re.compile(r"(?i)\btx(?:id)?s?\b|\btransactions?\b|\bmined\b|\bsent\b|\bpaid\b")
_HEADING = re.compile(r"^\s{0,3}#{1,6}\s+(\S.*)$")
_DIGEST_HEADING = re.compile(r"(?i)\bapks?\b|\baabs?\b|sha-?256|\bdigests?\b|\bchecksums?\b|\bhash(?:es)?\b")
_LIST_BLOCK_LINE = re.compile(r"^\s*(?:[-*+]\s|\d+[.)]\s|$)|^\s{2,}\S")
_HEADING_REACH = 40  # lines
# a key=value line whose key ENDS in apk, `on_phone_apk=<hex> (T4c 3df251d7f)`: apk is the last `_`, `-` or `.`
# separated part of the key right before the value (`\bapk\b` does not see it inside on_phone_apk)
_APK_KEY_BEFORE = re.compile(r"""(?i)(?:^|[^A-Za-z0-9_.-])(?:[A-Za-z0-9]+[_.-])*apks?["']?\s*[=:]\s*["'`]?$""")
# a JSON array of digests, one element per line, opened by a key that names a digest (the release gate report):
#   "notes_sha256": [
#     "<hex>",
_ARRAY_ITEM_LINE = re.compile(r"""^\s*["'][0-9a-fA-F]{64}["']\s*,?\s*$""")
# The key names a digest when the word is a part of its own (review of 13 Oct 2026: "shares" and "shared_notes" hold
# the letters only), and never when it speaks of transactions ("tx_hashes": such a value is a transaction id).
_ARRAY_OPEN = re.compile(r"""["']([^"']*)["']\s*[:=]\s*\[\s*$""")
_KEY_PART_BREAK = re.compile(r"[_.]+|(?<=[a-z0-9])(?=[A-Z])")  # notes_sha256, apk.digest, fileHashes
_DIGEST_KEY_WORD = re.compile(r"(?i)\b(?:sha-?\d+(?:sums?)?|hash(?:es)?|digests?|checksums?)\b")
_ARRAY_REACH = 500  # lines
# a Maven checksum sidecar: a `*.sha256` file that holds nothing but one digest (no file name)
_SIDECAR_TEXT = re.compile(r"\s*[0-9a-fA-F]{64}\s*")
# a label that speaks of a key is never a digest label for these rules (wider than _SECRET_WORDS on purpose)
_KEYISH = re.compile(r"(?i)key|token|secret|seed|passw|priv|mnemonic|\bpins?\b")
# Checksum files (ZC-701). A digest line is taken for one because of the NAME of the file it stands in, never because of
# its shape alone: a 64-hex value is also what a transaction id or a key looks like. The file is the one scanned or,
# inside a unified diff, the one the hunk belongs to (a diff's `+` in front of 52 digests gave 52 hard hits and made a
# review bundle unsendable). Such a line is a SOFT hit, checksum-digest: counted, so it stays visible; never blocking.
#   SHA256SUMS, EXPECTED-SHA256SUMS, SHA256SUMS-3.0.0, sha256sums.txt, SHA512SUMS, CHECKSUMS, checksums.txt
# ZC-779: a manifest file by its name counts like a checksum file (MANIFEST, MANIFEST.txt, x.manifest, manifest.json,
# release-manifest.json; not AndroidManifest.xml, mymanifest.txt or manifesto.json: the word is a part of its own).
_CHECKSUM_WORD = r"(?:sha(?:1|224|256|384|512)sums?|checksums?|manifest)"
_CHECKSUM_FILE = re.compile(rf"(?i)(?:^|[._-]){_CHECKSUM_WORD}(?:[._-]|$)")
# ZC-779, review of 13 Oct 2026: the name rule holds only for a file that can be a list. Its file type (what follows
# the last dot) is none, `txt` or `json`; the word itself (bundle.manifest) and a number (the version at the end of
# SHA256SUMS-3.0.0-nu7-zchat.1) are no file type. Manifest.kt, checksums.py, MANIFEST.MF, manifest.xml: not covered.
_LIST_FILE_TYPE = re.compile(rf"(?i)txt|json|\d+|{_CHECKSUM_WORD}")
# what may follow the digest on its line: nothing, or white space and the file's name (`*name` in binary mode)
_CHECKSUM_REST = re.compile(r"(?:[ \t]+\*?\S.*)?\s*")
_DIFF_HUNK = re.compile(r"^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@")
# a secret-named constant holding a URL (NEAR_TOKENS_URL = 'https://…') is a key literal only when the URL carries a
# key: a key-named query parameter, credentials, or a key-shaped part of its path or query (ZC-313)
_URL_VALUE = re.compile(r"(?i)^[a-z][a-z0-9+.-]*://([^/?#\s]*)(.*)$")
_KEY_PARAM = re.compile(r"(?i)[?&;][\w.-]*(?:key|token|secret|passw(?:or)?d|pwd|auth|sig(?:nature)?|credential)"
                        r"[\w.-]*=([^&#\s]+)")
_KEY_SHAPED = re.compile(r"(?=[^A-Za-z]*[A-Za-z])(?=\D*\d)[A-Za-z0-9_-]{20,}")


def _is_file_host(host: str) -> bool:
    host = host.lower().rstrip(".")
    return any(host == h or host.endswith("." + h) for h in FILE_HOSTS)


def _in_file_url_path(ln: str, start: int, end: int) -> bool:
    for u in _URL_PATH.finditer(ln):
        if u.start(2) <= start and end <= u.end(2):
            return _is_file_host(u.group(1))
    return False


def _under_package_block(lines: list[str], i: int) -> bool:
    above = []
    for ln in reversed(lines[max(0, i - 4):i]):
        if not ln.strip():
            break
        above.append(ln)
    return any(_APP_PACKAGE.search(a) for a in above) and any(_VERSION_CODE.search(a) for a in above)


def _digest_columns(lines: list[str]) -> dict[int, set[int]]:
    """Line index -> the cells (numbered by the `|` before them) whose table header names a digest."""
    out: dict[int, set[int]] = {}
    cols: set[int] = set()
    for i, ln in enumerate(lines):
        if i and "|" in ln and "|" in lines[i - 1] and _TABLE_RULE.match(ln):
            cols = {k for k, cell in enumerate(lines[i - 1].split("|")) if _DIGEST_NAME.search(cell)}
        elif cols and "|" in ln:
            out[i] = cols
        else:
            cols = set()
    return out


def _manifest_map_key(before: str, after: str) -> bool:
    """The hex is a quoted mapping KEY and its value a quoted label that names the MANIFEST (ZC-408)."""
    quote = before[-1:]
    if quote not in ("'", '"') or after[:1] != quote:
        return False
    label = _MAP_LABEL_AFTER.match(after[1:])
    return bool(label and _MANIFEST_WORD.search(label.group(2))
                and not _SECRET_WORDS.search(label.group(2)) and not _KEYISH.search(label.group(2)))


def _under_digest_heading(lines: list[str], i: int) -> bool:
    """lines[i] belongs to a list right under a heading that names APKs or digests (ZC-408)."""
    for ln in reversed(lines[max(0, i - _HEADING_REACH):i]):
        heading = _HEADING.match(ln)
        if heading:
            return bool(_DIGEST_HEADING.search(heading.group(1)) and not _KEYISH.search(heading.group(1))
                        and not _TX_LABEL.search(heading.group(1)))
        if not _LIST_BLOCK_LINE.match(ln):
            return False
    return False


def _in_digest_array(lines: list[str], i: int) -> bool:
    """lines[i] is one element of a JSON array of digests whose opening line names a digest (ZC-408)."""
    if not _ARRAY_ITEM_LINE.match(lines[i]):
        return False
    for ln in reversed(lines[max(0, i - _ARRAY_REACH):i]):
        if not _ARRAY_ITEM_LINE.match(ln):
            opened = _ARRAY_OPEN.search(ln)
            words = _KEY_PART_BREAK.sub(" ", opened.group(1)) if opened else ""
            return bool(_DIGEST_KEY_WORD.search(words)) and not _TX_LABEL.search(words) and not _KEYISH.search(ln)
    return False


def _digest_context(lines: list[str], i: int, m: re.Match, digest_cell) -> bool:
    """True when the 64-hex match `m` on lines[i] stands where a file digest is printed (see the rules above)."""
    ln = lines[i]
    v, before, after = m.group(0), ln[: m.start()], ln[m.end():]
    return bool(
        v.startswith(_BLOCK_HASH_ZEROS)
        or (before in ("", "\\") and _SHASUM_LINE.match(ln))
        or (_SUM_BEFORE.match(before) and _SUM_AFTER.match(after))
        or (_ARTIFACT_BEFORE.match(before) and _ARTIFACT_AFTER.match(after))
        or _APK_ID_AFTER.match(after)
        or (_NIP94_TAG_BEFORE.search(before) and _NIP94_TAG_AFTER.match(after))
        or ("://" in before and _in_file_url_path(ln, m.start(), m.end()))
        or (_BARE_HEX_LINE.match(ln) and _under_package_block(lines, i))
        or ("|" in before and digest_cell(i, before.count("|")))
        # ZC-408
        or (_SUM_BEFORE.match(before) and _SIZED_ROW_AFTER.match(after))
        or _manifest_map_key(before, after)
        or _in_digest_array(lines, i)
        or (not _KEYISH.search(before) and (
            _APK_KEY_BEFORE.search(before)
            or (_LABELLED_ITEM_BEFORE.match(before) and _ITEM_AFTER.match(after) and not _TX_LABEL.search(before)
                and _under_digest_heading(lines, i)))))


def _diff_path(name: str) -> str | None:
    """The file that a `--- ` or `+++ ` line of a unified diff names; None for /dev/null."""
    name = name.split("\t", 1)[0].strip().strip('"')  # plain `diff -u` appends a tab and a time; git quotes odd names
    if name == "/dev/null":
        return None
    return name[2:] if name[:2] in ("a/", "b/") else name


def _hunk_files(lines: list[str]) -> dict[int, str]:
    """Line index -> the file of the unified-diff hunk that the line belongs to, for every line inside a hunk
    (ZC-701). A hunk is what its `@@ -a,b +c,d @@` header counts, right after a `--- ` / `+++ ` pair or after the
    hunk before it: b lines of context and removals, d lines of context and additions. What stands after that count
    is not part of it. The file is the new one, or the old one when the diff deletes the file."""
    if not any(ln.startswith("@@ ") for ln in lines):
        return {}
    out: dict[int, str] = {}
    old = file = None
    pending = False          # a `--- ` line came, its `+++ ` line is due
    left_old = left_new = 0  # lines of the running hunk still to come
    for i, ln in enumerate(lines):
        mark = ln[:1]
        if left_old > 0 or left_new > 0:
            if mark == "\\":  # "\ No newline at end of file"
                continue
            if mark in (" ", "-", "+", ""):
                o, n = left_old - (mark != "+"), left_new - (mark != "-")
                if o >= 0 and n >= 0:
                    left_old, left_new = o, n
                    out[i] = file
                    continue
            left_old = left_new = 0  # the text leaves the hunk before its count is used up
        m = _DIFF_HUNK.match(ln)
        if m and file:
            left_old, left_new = (1 if g is None else int(g) for g in m.groups())
        elif ln.startswith("--- "):
            old, file, pending = _diff_path(ln[4:]), None, True
        elif ln.startswith("+++ ") and pending:
            file, pending = _diff_path(ln[4:]) or old, False
        elif mark != "\\":
            file, pending = None, False
    return out


def _is_checksum_file(path: str) -> bool:
    """A checksum file by its NAME (ZC-701): SHA256SUMS, EXPECTED-SHA256SUMS, sha256sums.txt, CHECKSUMS …; or a manifest
    file by its name (ZC-779): MANIFEST, MANIFEST.txt, manifest.json … Only a name with no file type, `.txt` or
    `.json` (_LIST_FILE_TYPE)."""
    name = path.replace(os.sep, "/").rsplit("/", 1)[-1]
    stem, dot, file_type = name.rpartition(".")
    if stem and dot and not _LIST_FILE_TYPE.fullmatch(file_type):
        return False  # a code file or any other file type: the name exempts nothing (review of 13 Oct 2026)
    return bool(_CHECKSUM_FILE.search(name))


# Digests in JSON files (ZC-779). On 9 Oct 2026 the nightly scan of the evidence folder gave 1,901,950 hard hits,
# almost all 64-hex digests in machine-written JSON files of capture folders. As for checksum files, the NAME decides
# and never the shape of the value: the name of the key the value stands under, or the name of the file.
#   a key that names a digest   sha256, hash, digest or checksum, with or without a prefix or suffix (tracked_sha256,
#                               source_hashes, sha256_expected): the value's own key or one that encloses it, so a map
#                               from file names to digests and a list under such a key count
#   a checksum or manifest file by its name (_CHECKSUM_FILE): every value of the document, also a digest that is a key
#   a key named like a secret   (_KEYISH: key, token, secret, seed, priv…) is never exempt, and nothing below it is
#                               until a deeper key names a digest again; a key that names both is a secret's
#   a file path as a key        (it holds a `/`) is a file's name, not a field's: it changes nothing
# A value that also stands where no name covers it (another key, a list, inside a longer string, as a key) is exempt
# nowhere in that file. Only a `*.json` file that parses as one document is read this way.
_DIGEST_KEY = re.compile(r"(?i)sha-?(?:1|224|256|384|512)|hash|digest|checksum")


def _json_digest_values(text: str, named_file: bool) -> frozenset[str] | None:
    """The 64-hex strings of a JSON document that a name covers (the rules above); None when the text is no JSON
    document. `named_file`: the file is a checksum or manifest file by its name."""
    try:
        doc = json.loads(text)
    except (ValueError, RecursionError):
        return None
    covered: set[str] = set()
    bare: set[str] = set()
    todo = [(doc, named_file)]
    while todo:
        node, digest = todo.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                key = str(key)
                if _HEX64.fullmatch(key):
                    (covered if digest else bare).add(key)
                else:
                    bare.update(_HEX64.findall(key))
                if "/" in key and not re.search(r"\s", key):
                    todo.append((value, digest))  # a file's name
                elif _KEYISH.search(key):
                    todo.append((value, False))
                else:
                    todo.append((value, digest or bool(_DIGEST_KEY.search(key))))
        elif isinstance(node, list):
            todo.extend((value, digest) for value in node)
        elif isinstance(node, str):
            if _HEX64.fullmatch(node):
                (covered if digest else bare).add(node)
            else:
                bare.update(_HEX64.findall(node))
    return frozenset(covered - bare)


def _checksum_entry(ln: str, m: re.Match, hunk_of: str | None, in_checksum_file: bool) -> bool:
    """ZC-701: the 64-hex match `m` on the line `ln` is the digest of a checksum-list line (it starts the line, and
    nothing or a file name follows it) in a checksum file by its NAME. `hunk_of`: the file of the unified-diff hunk
    the line stands in (_hunk_files), None outside a hunk; `in_checksum_file`: the text itself is such a file. Inside
    a hunk the line starts after its `+`, `-` or space, and only the hunk's file counts. The output hook shares this
    rule (what `git show` prints and what a Read of a .diff shows)."""
    if hunk_of is None and not in_checksum_file:
        return False
    at = 0 if hunk_of is None else 1
    at += ln.startswith("\\", at)  # sha256sum's mark in front of the digest of a name with special characters
    return bool(m.start() == at and _CHECKSUM_REST.fullmatch(ln, m.end())
                and (hunk_of is None or _is_checksum_file(hunk_of)))


def _url_holds_key(url: str) -> bool:
    """For a secret-named URL constant: True when the URL carries a key (a key-named query parameter that is not a
    placeholder, credentials, or a key-shaped part of the path or query). Its scheme and host never count, and
    neither does a digest in the path of a file host."""
    m = _URL_VALUE.match(url)
    if not m:
        return True
    authority, rest = m.group(1), m.group(2)
    if "@" in authority:
        return True
    for p in _KEY_PARAM.finditer(rest):
        if not (_URL_PLACEHOLDER.match(p.group(1)) or p.group(1).startswith(("$", "<", "{", "%"))):
            return True
    file_host = _is_file_host(authority.split(":")[0])
    return any(_KEY_SHAPED.fullmatch(part) and not (file_host and _HEX64.fullmatch(part))
               for part in re.split(r"[/?&=#;.,:+~]", rest))


def placeholder_hex(value: str) -> bool:
    v = value.lower()
    if len(set(v)) <= 4:
        return True
    return any(all(v[i] == v[i % p] for i in range(len(v))) for p in range(1, 33))


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def phrase_runs(text: str) -> list[tuple[int, int, list[str]]]:
    """(start offset, end offset, words) for every run of >= 12 BIP39 words separated only by phrase gaps
    (spaces, line breaks, quotes, commas, list numbers, string '+'). A sorted list is a word list, not a
    phrase."""
    runs = []
    cur: list[str] = []
    start = prev_end = 0
    for m in _WORD.finditer(text):
        w = m.group(0)
        lw = w.lower()
        if lw in IDX and w in (lw, lw.capitalize(), lw.upper()):
            if not (cur and _PHRASE_GAP.fullmatch(text, prev_end, m.start())):
                if len(cur) >= 12:
                    runs.append((start, prev_end, cur))
                cur, start = [], m.start()
            cur.append(lw)
        else:
            if len(cur) >= 12:
                runs.append((start, prev_end, cur))
            cur = []
        prev_end = m.end()
    if len(cur) >= 12:
        runs.append((start, prev_end, cur))
    return [r for r in runs if not all(a < b for a, b in zip(r[2], r[2][1:]))]


def _seed_class(run: list[str], allow: Allow, fixture_marked: bool) -> tuple[str, int]:
    """('hard'|'soft'|'allowed', n): hard when a 12..24-word window passes the checksum, has at least n-1
    distinct words and is not covered by a public or allow-listed phrase."""
    if allow.allows("bip39-phrase", " ".join(run)):
        return "allowed", len(run)  # the p11 allow list hashes the whole run
    covered: set[int] = set()
    for n in (24, 21, 18, 15, 12):
        for s in range(len(run) - n + 1):
            fp = fingerprint(" ".join(run[s:s + n]))
            if fp in PUBLIC_PHRASES or allow.allows("bip39-phrase", " ".join(run[s:s + n])):
                covered.update(range(s, s + n))
    for n in (24, 21, 18, 15, 12):
        for s in range(len(run) - n + 1):
            if set(range(s, s + n)) <= covered:
                continue
            w = run[s:s + n]
            if len(set(w)) >= n - 1 and bip39_valid(w):
                return ("allowed", n) if fixture_marked else ("hard", n)
    return ("allowed", len(run)) if covered else ("soft", len(run))


def _address_candidates(text: str):
    for m in _BECH_ADDR.finditer(text):
        s = m.group(0)
        spec, min_len = ADDRESS_SPECS[m.group(1)]
        if len(s) >= min_len and bech32_verify(s) == spec:
            yield m.start(), s
    for m in _T_ADDR.finditer(text):
        body = b58check_decode(m.group(0))
        if body is not None and len(body) == 22 and body[:2] in T_ADDR_VERSIONS:
            yield m.start(), m.group(0)


def _addresses(text: str) -> list[tuple[int, str]]:
    out: dict[str, int] = {}
    for off, a in _address_candidates(text):
        out.setdefault(a, _line_of(text, off))
    joined = _CONCAT.sub("", text)
    if joined != text:
        for off, a in _address_candidates(joined):
            if a not in out:
                i = text.find(a[:24])
                out[a] = _line_of(text, i) if i >= 0 else _line_of(joined, off)
    return [(ln, a) for a, ln in out.items()]


# ZC-2124: JSON Web Tokens, also when a source file or a wrapped terminal line splits one over several lines.
# A token starts with `eyJ` (base64url of `{"`) where no base64 character stands before it, so the `eyJ` inside a
# base64 image blob or a `data:…;base64,` URI of JSON does not start one. From there the join follows a string
# concatenation (`"…" +`, `+ "…"`, Python's adjacent literals) or, for a long line that is token text up to its
# end, a plain wrapped line that is token text as a whole; at most JWT_WINDOW lines. The joined text is a JWT when
# it has three dotted segments and the first one decodes to a JSON header (alg, typ, kid or enc). Apart from that,
# a line that holds nothing but base64url text (dotted segments, one of 40+ characters) with upper, lower and
# digits (not hex: git and file digests stay quiet), right after a line where a token starts, also a masked
# `eyJ…`, or after such a line, is the payload or signature of a token whose shape the join could not see.
# Kinds: `jwt` on one line, `jwt-split` across lines. Values are never returned.
JWT_WINDOW = 8
_JWT_START = re.compile(r"(?<![A-Za-z0-9+/=_-])(?<!base64,)eyJ[A-Za-z0-9_-]{10,}")  # not a JSON data: URI
_JWT_SHAPE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}")
_JWT_RUN = re.compile(r"[A-Za-z0-9_.-]*")
_JWT_QUOTED_END = re.compile(r"""^["'`]\s*\+?\s*\\?\s*$""")
_JWT_LINE_PREFIX = re.compile(r"""^(?:[^\s:]+:\d+[:-])?\s*(?:\d+\t\s*)?(?:\+\s*)?(?:["'`])?""")
_JWT_LONE = re.compile(r"""^\.?([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)\.?(?:["'`])?\s*[+,;)]*\s*\\?\s*$""")
# what arms the lone-segment rule: any token start, also a masked one (`eyJ…`), outside a JSON data: URI
_JWT_ARM = re.compile(r"(?<![A-Za-z0-9+/=_-])(?<!base64,)eyJ")
_HEX_ONLY = re.compile(r"[0-9a-fA-F]+")
_JWT_HEADER_KEYS = ("alg", "typ", "kid", "enc")


def _jwt_header(segment: str) -> bool:
    try:
        obj = json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
    except (ValueError, TypeError):
        return False
    return isinstance(obj, dict) and any(k in obj for k in _JWT_HEADER_KEYS)


def _jwt_join(lines: list[str], i: int, start: int) -> tuple[str, list[int]]:
    """The token text from lines[i][start:] on, joined over concatenated or wrapped lines; and the end offset of
    each line's piece in it."""
    run = _JWT_RUN.match(lines[i], start).group(0)
    parts, ends = [run], [len(run)]
    rest = lines[i][start + len(run):].rstrip()
    j = i
    while j + 1 < len(lines) and j - i < JWT_WINDOW:
        quoted = bool(_JWT_QUOTED_END.match(rest))
        if not quoted and (rest or len(lines[j].rstrip()) < 40):
            break  # neither a concatenation nor a line wrapped at the token's end
        body = _JWT_LINE_PREFIX.sub("", lines[j + 1], count=1)
        piece = _JWT_RUN.match(body).group(0)
        tail = body[len(piece):].rstrip()
        if not piece or (quoted and not _JWT_QUOTED_END.match(tail)) or (not quoted and tail):
            break
        parts.append(piece)
        ends.append(ends[-1] + len(piece))
        rest, j = tail, j + 1
    return "".join(parts), ends


def _lone_segment(line: str) -> bool:
    m = _JWT_LONE.match(_JWT_LINE_PREFIX.sub("", line.rstrip(), count=1))
    if not m:
        return False
    s = m.group(1)
    if max(len(seg) for seg in s.split(".")) < 40:
        return False
    return (not _HEX_ONLY.fullmatch(s.replace(".", "")) and any(c.isupper() for c in s)
            and any(c.islower() for c in s) and any(c.isdigit() for c in s))


def jwt_hits(text: str) -> list[tuple[int, str]]:
    """(1-based line, 'jwt' | 'jwt-split') for every JWT in text, one per token or lone segment line."""
    if "eyJ" not in text:
        return []
    lines = text.split("\n")
    hits: dict[int, str] = {}
    used: set[int] = set()
    for i, ln in enumerate(lines):
        if "eyJ" not in ln:
            continue
        for m in _JWT_START.finditer(ln):
            joined, ends = _jwt_join(lines, i, m.start())
            jm = _JWT_SHAPE.match(joined)
            if not jm or not _jwt_header(jm.group(0).split(".", 1)[0]):
                continue
            last = next(k for k, e in enumerate(ends) if e >= jm.end())
            hits.setdefault(i, "jwt-split" if last else "jwt")
            used.update(range(i, i + last + 1))
    chain = 0  # lines left in which a lone segment still belongs to the token started above
    for i, ln in enumerate(lines):
        if chain and _lone_segment(ln):
            if i not in used:
                hits.setdefault(i, "jwt-split")
            chain -= 1
        else:
            chain = 0
        if "eyJ" in ln and _JWT_ARM.search(ln):
            chain = JWT_WINDOW
    return [(i + 1, k) for i, k in sorted(hits.items())]


@dataclass(frozen=True)
class Hit:
    label: str
    line: int
    kind: str
    severity: str  # "hard" | "soft"

    def format(self) -> str:
        return f"{self.label}:{self.line}\t{self.kind}\t{self.severity}"


def _find(text: str, path: str, known: dict[str, list[str]], allow: Allow) -> list[tuple[int, str, str]]:
    """(line, kind, severity) for every hit in `text`; `path` decides fixture and config rules."""
    lines = text.splitlines()
    fixture = bool(FIXTURE_PATH.search(path.replace(os.sep, "/")))
    config = path.endswith(_CONFIG_EXT) or os.path.basename(path).startswith(".env")
    # a `*.sha256` file that holds nothing but one digest: a Maven checksum sidecar (ZC-408)
    sidecar = path.lower().endswith(".sha256") and bool(_SIDECAR_TEXT.fullmatch(text))
    out: list[tuple[int, str, str]] = []

    def marked(n: int) -> bool:
        return fixture and 0 < n <= len(lines) and FAKE_MARKER in lines[n - 1]

    def add(n: int, kind: str, sev: str, value: str | None = None):
        if marked(n) or (value is not None and allow.allows(kind, value)):
            return
        out.append((n, kind, sev))

    table_cells: dict[int, set[int]] | None = None

    def digest_cell(i: int, cell: int) -> bool:
        nonlocal table_cells
        if table_cells is None:
            table_cells = _digest_columns(lines)  # only for a text with a 64-hex value left to judge
        return cell in table_cells.get(i, ())

    checksum_file = _is_checksum_file(path)
    hunk_file: dict[int, str] | None = None

    def checksum_line(i: int, m: re.Match) -> bool:
        nonlocal hunk_file
        if hunk_file is None:
            hunk_file = _hunk_files(lines)  # only for a text with a 64-hex value left to judge
        return _checksum_entry(lines[i], m, hunk_file.get(i), checksum_file)

    json_file = path.lower().endswith(".json")
    json_digests: frozenset[str] | None = None

    def json_digest(value: str) -> bool:
        """ZC-779: the value stands in this JSON file only where a key or the file's name says digest."""
        nonlocal json_digests
        if not json_file:
            return False
        if json_digests is None:  # only for a text with a 64-hex value that would be a hit
            json_digests = _json_digest_values(text, checksum_file) or frozenset()
        return value in json_digests

    # BIP39 phrases, within a line or one word per line
    for start, end, run in phrase_runs(text):
        n0, n1 = _line_of(text, start), _line_of(text, end)
        per_line = n1 - n0 + 1 >= 12
        if per_line and len(run) > 24:
            continue  # a word list, not a phrase
        cls, n = _seed_class(run, allow, marked(n0) or marked(n1))
        if cls == "allowed":
            continue
        kind = "bip39-phrase-one-word-per-line" if per_line else f"bip39-{n}-words"
        out.append((n0, kind, cls))

    for n, a in _addresses(text):
        add(n, "zcash-address", "soft" if fixture else "hard", a)

    for n, ln in enumerate(lines, start=1):
        for kind, rx in REGEX_HARD:
            for m in rx.finditer(ln):
                add(n, kind, "hard", m.group(0))
        if _PEM.search(ln):
            add(n, "pem-private-key", "hard")
        for m in _WIF.finditer(ln):
            body = b58check_decode(m.group(0))
            if body is not None and body[:1] == b"\x80" and len(body) in (33, 34):
                add(n, "wif-private-key", "hard", m.group(0))
        for m in _URL_CRED.finditer(ln):
            placeholder = _URL_PLACEHOLDER.match(m.group(2)) or m.group(2).startswith(("$", "<", "{", "%"))
            add(n, "url-with-credentials", "soft" if placeholder else "hard", m.group(0))
        for m in _HEX64.finditer(ln):
            before = ln[: m.start()]
            if placeholder_hex(m.group(0)) or _HASH_LABEL.search(before) or sidecar:
                continue
            if checksum_line(n - 1, m):
                add(n, "checksum-digest", "soft", m.group(0))
                continue
            if _SECRET_WORDS.search(before) or not (_PUBLIC_WORDS.search(ln)
                                                    or _digest_context(lines, n - 1, m, digest_cell)):
                if json_digest(m.group(0)):
                    add(n, "checksum-digest", "soft", m.group(0))
                else:
                    add(n, "hex64-secret", "soft" if fixture else "hard", m.group(0))
        # literal passwords and secret-named literals (hard outside fixtures); code shapes (soft)
        pw = False
        literal_pw = [m.group(2) for m in _PASSWORD_QUOTED.finditer(ln)]
        if config:
            literal_pw += [m.group(1) for m in _PASSWORD_BARE.finditer(ln)]
        for v in literal_pw:
            pw = True
            if fixture:
                add(n, "password-assignment", "soft", v)
            else:
                add(n, "password-literal", "hard", v)
        if not pw and _PASSWORD_SHAPE.search(ln):
            add(n, "password-assignment", "soft")
        ak = False
        for m in _NAMED_LITERAL.finditer(ln):
            v = m.group(3)
            if (_SECRET_NAME.search(m.group(1)) and re.search(r"[A-Za-z]", v) and re.search(r"\d", v)
                    and not placeholder_hex(v) and (not _URL_VALUE.match(v) or _url_holds_key(v))):
                ak = True
                add(n, "api-key-assignment" if fixture else "api-key-literal", "soft" if fixture else "hard", v)
        if not ak:
            for m in _APIKEY_SHAPE.finditer(ln):
                quoted = bool(m.group(1))
                v = m.group(2)
                if quoted and not fixture and re.search(r"\d", v) and re.search(r"[A-Za-z]", v):
                    add(n, "api-key-literal", "hard", v)
                else:
                    add(n, "api-key-assignment", "soft")
                break

    out += _known_hits(lines, known, allow)
    return out


def _known_hits(lines: list[str], known: dict[str, list[str]], allow: Allow | None = None) -> list[tuple[int, str, str]]:
    """`allow` (ZC-2063): a value its public-id line declares public under this NAME is not reported for this NAME.
    Without `allow` (the output hook) every known value is reported."""
    out = []
    for name, vals in known.items():
        for val in vals:
            if allow is not None and allow.public_known(name, val):
                continue
            sev = known_severity(name, val)
            found = False
            for ln in lines:
                if val not in ln:
                    continue
                found = True
                if sev == "soft" and name not in SOFT_KNOWN_NAMES:
                    for m in re.finditer(re.escape(val), ln):
                        b = ln[m.start() - 1:m.start()] if m.start() > 0 else ""
                        a = ln[m.end():m.end() + 1]
                        if not (b.isalnum() or a.isalnum()) and PIN_CONTEXT.search(ln[max(0, m.start() - 60):m.end() + 30]):
                            sev = "hard"
                            break
                if sev == "hard":
                    break
            if found:
                # no line number: short PINs collide with ordinary digits, and a pointer to the colliding
                # digits would reveal the PIN
                out.append((0, f"KNOWN-VALUE:{name}", sev))
    return out


_DEFAULT_KNOWN: dict[str, list[str]] | None = None


def _resolve_known(known):
    global _DEFAULT_KNOWN
    if known is None:
        if _DEFAULT_KNOWN is None:
            _DEFAULT_KNOWN = default_known()
        return _DEFAULT_KNOWN
    return {k: ([v] if isinstance(v, str) else list(v)) for k, v in known.items()}


def scan_text(text: str, label: str, path: str | None = None, known=None, allow: Allow | None = None,
              line_offset: int = 0) -> list[Hit]:
    """Hits in `text`. `label` is printed; `path` (default: label) decides the fixture/config rules."""
    known = _resolve_known(known)
    allow = allow if allow is not None else load_allow()
    hits = []
    seen = set()
    for n, kind, sev in _find(text, path if path is not None else label, known, allow):
        line = 0 if n == 0 else n + line_offset
        key = (line, kind, sev)
        if key not in seen:
            seen.add(key)
            hits.append(Hit(label, line, kind, sev))
    return hits


def secret_file_hit(label: str, path: str) -> Hit | None:
    if SECRET_FILE.search(path.replace(os.sep, "/")):
        return Hit(label, 0, "secret-file", "hard")
    return None


# ---------------------------------------------------------------------------------------------------------
# Sources

def _decode(blob: bytes) -> str | None:
    if b"\x00" in blob[:8192] or len(blob) > MAX_BYTES:
        return None
    return blob.decode("utf-8", errors="ignore")


def scan_files(paths, known=None, allow=None, exclude=()):
    """Hits in the files under `paths`. `exclude`: folders that are not walked at all; only the nightly evidence scan
    passes one, for a vendored public clone (ZC-537). The command line has no switch for it."""
    skip = {os.path.abspath(str(p)) for p in exclude}
    for root in paths:
        if os.path.abspath(str(root)) in skip:
            continue
        if os.path.isfile(root):
            candidates = [root]
        else:
            candidates = []
            for d, dirs, files in os.walk(root):
                dirs[:] = sorted(x for x in dirs
                                 if x not in SKIP_DIRS and not (skip and os.path.abspath(os.path.join(d, x)) in skip))
                candidates += [os.path.join(d, f) for f in sorted(files)]
        for p in candidates:
            h = secret_file_hit(p, p)
            if h:
                yield h
            if os.path.splitext(p)[1].lower() in BINARY_EXT:
                continue
            try:
                if os.path.getsize(p) > MAX_BYTES:
                    continue
                with open(p, "rb") as fh:
                    text = _decode(fh.read())
            except OSError:
                continue
            if text is not None:
                yield from scan_text(text, p, known=known, allow=allow)


def _git(repo, *args) -> bytes:
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, timeout=3600)
    if r.returncode != 0:
        raise RuntimeError(f"git {args[0]} failed: {r.stderr.decode(errors='replace').strip()[:200]}")
    return r.stdout


_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def _scan_diff(stream, label_for, known, allow, commit_allowed=None):
    """Parse `git diff/log -p -U0` output; scan each block of added lines. `label_for(commit, path)`."""
    known = _resolve_known(known)
    allow = allow if allow is not None else load_allow()
    commit, path, new_line = "", "", 0
    block: list[str] = []
    block_start = 0

    def flush():
        nonlocal block
        if block and path:
            for h in scan_text("\n".join(block) + "\n", label_for(commit, path), path=path, known=known,
                               allow=allow, line_offset=block_start - 1):
                if commit_allowed is None or not commit_allowed(commit, path, h.kind):
                    yield h
        block = []

    for raw in stream:
        line = raw.rstrip("\n")
        if line.startswith("@@COMMIT "):
            yield from flush()
            commit = line.split()[1]
            continue
        if line.startswith("diff --git "):
            yield from flush()
            path = ""
            continue
        if line.startswith("+++ "):
            yield from flush()
            path = line[6:] if line.startswith("+++ b/") else ""
            if path:
                h = secret_file_hit(label_for(commit, path), path)
                if h and (commit_allowed is None or not commit_allowed(commit, path, h.kind)):
                    yield h
            continue
        m = _HUNK.match(line)
        if m:
            yield from flush()
            new_line = int(m.group(1))
            block_start = new_line
            continue
        if line.startswith("+") and path:
            if not block:
                block_start = new_line
            block.append(line[1:])
            new_line += 1
        elif line.startswith("-") or line.startswith("\\"):
            continue
        else:
            yield from flush()
    yield from flush()


def _popen(repo, args):
    return subprocess.Popen(["git", "-C", str(repo), *args], stdout=subprocess.PIPE, text=True, errors="ignore")


_DIFF_OPTS = ["-p", "-U0", "--no-color", "--no-ext-diff", "--no-textconv", "--no-renames"]


def scan_git(repo, rng=None, known=None, allow=None):
    allow = allow if allow is not None else load_allow()
    args = ["log", *(rng.split() if rng else ["--all"]), *_DIFF_OPTS, "--format=@@COMMIT %H"]
    proc = _popen(repo, args)
    try:
        yield from _scan_diff(proc.stdout, lambda c, p: f"{repo}@{c[:9]}:{p}", known, allow,
                              commit_allowed=allow.allows_history)
    finally:
        proc.stdout.close()
        if proc.wait() != 0:
            raise RuntimeError("git log failed")


def scan_staged(repo=".", known=None, allow=None):
    proc = _popen(repo, ["diff", "--cached", *_DIFF_OPTS, "--diff-filter=ACMR"])
    try:
        yield from _scan_diff(proc.stdout, lambda c, p: p, known, allow)
    finally:
        proc.stdout.close()
        if proc.wait() != 0:
            raise RuntimeError("git diff --cached failed")


def scan_tree(repo, rev, known=None, allow=None):
    known = _resolve_known(known)
    allow = allow if allow is not None else load_allow()
    for entry in _git(repo, "ls-tree", "-r", "-z", rev).split(b"\x00"):
        if not entry:
            continue
        meta, p = entry.split(b"\t", 1)
        _mode, typ, sha = meta.split()
        path = p.decode(errors="replace")
        if typ != b"blob":
            continue
        h = secret_file_hit(path, path)
        if h:
            yield h
        if os.path.splitext(path)[1].lower() in BINARY_EXT:
            continue
        text = _decode(_git(repo, "cat-file", "blob", sha.decode()))
        if text is not None:
            yield from scan_text(text, path, known=known, allow=allow)


# ---------------------------------------------------------------------------------------------------------
# CLI

def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    summary = hard_only = False
    allow_path = None
    rest = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--summary":
            summary = True
        elif a == "--hard-only":
            hard_only = True
        elif a == "--no-known":
            os.environ["SCAN_NO_KNOWN"] = "1"
        elif a == "--allow" and i + 1 < len(args):
            allow_path = args[i + 1]
            i += 1
        elif a == "--staged":
            rest = ["staged", "."] + rest
        else:
            rest.append(a)
        i += 1
    if not rest:
        print(__doc__, file=sys.stderr)
        return 2
    mode, params = rest[0], rest[1:]
    try:
        allow = load_allow(allow_path)
        if mode == "files" and params:
            hits = scan_files(params, allow=allow)
        elif mode == "git" and 1 <= len(params) <= 2:
            hits = scan_git(params[0], params[1] if len(params) > 1 else None, allow=allow)
        elif mode == "tree" and len(params) == 2:
            hits = scan_tree(params[0], params[1], allow=allow)
        elif mode == "staged" and len(params) <= 1:
            hits = scan_staged(params[0] if params else ".", allow=allow)
        elif mode == "stdin" and len(params) == 1:
            hits = scan_text(sys.stdin.read(), params[0], allow=allow)
        else:
            print(__doc__, file=sys.stderr)
            return 2
        counts = collections.Counter()
        paths = collections.defaultdict(set)
        n_hard = 0
        for h in hits:
            n_hard += h.severity == "hard"
            if summary:
                counts[(h.severity, h.kind)] += 1
                paths[(h.severity, h.kind)].add(h.label)
            elif h.severity == "hard" or not hard_only:
                print(h.format(), flush=True)
    except (RuntimeError, ValueError, OSError) as e:
        print(f"secret_scan: error: {e}", file=sys.stderr)
        return 2
    if summary:
        for (sev, kind), c in sorted(counts.items()):
            print(f"{sev}\t{kind}\t{c} hits\t{len(paths[(sev, kind)])} paths")
        print(f"total\thard={sum(c for (s, _), c in counts.items() if s == 'hard')}\t"
              f"soft={sum(c for (s, _), c in counts.items() if s == 'soft')}")
    return 1 if n_hard else 0


if __name__ == "__main__":
    sys.exit(main())
