#!/usr/bin/env python3
"""
dicgenerat — генератор словарей для credential-спрея.

Тянет креды воркспейса с сервера PenHub и строит два файла:
  <ws>_base.txt    — уникальные пароли/логины/домены/DPAPI
  <ws>_mutated.txt — модифицированные логины (транслит → раскладка → хвосты)

Standalone операторский скрипт. Зависимости: только stdlib.
Не входит в инсталлер/cron.
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
from configparser import ConfigParser
from pathlib import Path

CONF_FILE = Path.home() / ".nxc-collector.conf"

EMPTY_PASSWORD = "<empty_password>"

_SKIP_USERS = {"guest", "гость", "defaultaccount", "wdagutilityaccount", ""}


# ── Extraction helpers ──────────────────────────────────────────────────────

def is_skip_user(name: str) -> bool:
    return (name or "").casefold() in _SKIP_USERS


def plaintext_of(row: dict) -> "str | None":
    """Извлечь plaintext-пароль из cred/custom-строки.

    plaintext -> password; hash + brutforced -> brutforced; чистый hash -> None.
    Пустые и сентинел <empty_password> -> None.
    """
    ct = (row.get("credtype") or "").lower()
    val = row.get("brutforced") if ct == "hash" else row.get("password")
    if not val or val == EMPTY_PASSWORD:
        return None
    return val


def build_base(creds: list, custom: list, dpapi: list) -> list:
    """File 1: уникальные пароли (вкл. bruteforced) + логины (минус skip) +
    домены (lower) + DPAPI логины/пароли. Отсортированный уникальный список."""
    out: set = set()
    for row in list(creds) + list(custom):
        pw = plaintext_of(row)
        if pw:
            out.add(pw)
        u = row.get("username") or ""
        if u and not is_skip_user(u):
            out.add(u)
        d = (row.get("domain") or "").lower()
        if d:
            out.add(d)
    for row in dpapi:
        pw = row.get("password") or ""
        if pw and pw != EMPTY_PASSWORD:
            out.add(pw)
        u = row.get("username") or ""
        if u and not is_skip_user(u):
            out.add(u)
    return sorted(out)


# ── Login strip (-sb / -sa / -b / -a) ───────────────────────────────────────

def strip_login(login: str, sb=None, sa=None, b: int = 0, a: int = 0) -> str:
    """Один детерминированный stem. Порядок: sb -> sa -> b -> a.
    Сепаратор не найден -> без изменений. Может вернуть ''."""
    s = login
    if sb and sb in s:
        s = s[s.find(sb) + len(sb):]
    if sa and sa in s:
        s = s[:s.rfind(sa)]
    if b:
        s = s[b:]
    if a:
        s = s[:max(0, len(s) - a)]
    return s


# ── Transliteration EN → RU ─────────────────────────────────────────────────
# Ambiguous tokens branch into multiple russian variants (primary first).
_MULTI = [
    ("shch", ["щ"]),
    ("sch",  ["щ"]),
    ("sh",   ["ш", "щ"]),
    ("ch",   ["ч"]),
    ("zh",   ["ж"]),
    ("kh",   ["х"]),
    ("ts",   ["ц"]),
    ("yo",   ["ё", "е"]),
    ("yu",   ["ю"]),
    ("ya",   ["я"]),
    ("ye",   ["е", "э"]),
    ("ph",   ["ф"]),
]
_SINGLE = {
    "a": ["а"], "b": ["б"], "c": ["к", "ц", "с"], "d": ["д"], "e": ["е", "э"],
    "f": ["ф"], "g": ["г"], "h": ["х", "г"], "i": ["и"], "j": ["дж", "й"],
    "k": ["к"], "l": ["л"], "m": ["м"], "n": ["н"], "o": ["о"], "p": ["п"],
    "q": ["к"], "r": ["р"], "s": ["с"], "t": ["т"], "u": ["у"], "v": ["в"],
    "w": ["в", "у"], "x": ["кс", "х"], "y": ["ы", "й"], "z": ["з"],
}
_SURNAME_ENDINGS = [("eff", "ев"), ("off", "ов"), ("of", "ов")]
_SOFT_CLUSTERS = ["зм", "нм", "см"]


def _translit_core(word: str, cap: int) -> list:
    variants = [""]
    i = 0
    while i < len(word):
        step, alts = 1, None
        for digr, a in _MULTI:
            if word.startswith(digr, i):
                step, alts = len(digr), a
                break
        if alts is None:
            alts = _SINGLE.get(word[i], [word[i]])
        variants = [v + alt for v in variants for alt in alts][:cap]
        i += step
    return variants


def translit_variants(word: str, cap: int = 8) -> list:
    word = word.lower()
    out = list(_translit_core(word, cap))

    # surname endings: add stem-translit + russian ending
    for eng, rus in _SURNAME_ENDINGS:
        if word.endswith(eng):
            for stem in _translit_core(word[: -len(eng)], cap):
                out.append(stem + rus)
            break

    # soft-sign clusters: insert ь after the first consonant of the cluster
    for base in list(out):
        for cl in _SOFT_CLUSTERS:
            idx = base.find(cl)
            if idx != -1:
                out.append(base[: idx + 1] + "ь" + base[idx + 1:])

    seen, dedup = set(), []
    for v in out:
        if v and v not in seen:
            seen.add(v)
            dedup.append(v)
    return dedup[:cap]


# ── Keyboard layout RU → EN (both cases) ────────────────────────────────────
_EN = "`qwertyuiop[]asdfghjkl;'zxcvbnm,./~QWERTYUIOP{}ASDFGHJKL:\"ZXCVBNM<>?"
_RU = "ёйцукенгшщзхъфывапролджэячсмитьбю.ЁЙЦУКЕНГШЩЗХЪФЫВАПРОЛДЖЭЯЧСМИТЬБЮ,"
assert len(_EN) == len(_RU), "layout maps must be equal length"
_LAYOUT = {ru: en for ru, en in zip(_RU, _EN)}


def to_en_layout(text: str) -> str:
    return "".join(_LAYOUT.get(ch, ch) for ch in text)


# ── Tail enrichment ─────────────────────────────────────────────────────────
CHARSET_B = "0123456789!@#$%&*_-."


def years_since(now_year: int, start: int = 1970) -> list:
    return [str(y) for y in range(start, now_year + 1)]


def append_tails(s: str, charset: str, years: list):
    """s + хвосты 1/2/3 из charset + годовые хвосты."""
    yield s
    for c1 in charset:
        yield s + c1
        for c2 in charset:
            yield s + c1 + c2
            for c3 in charset:
                yield s + c1 + c2 + c3
    for y in years:
        yield s + y


# ── Full mutation pipeline for one login ────────────────────────────────────

def mutate_login(login: str, sb=None, sa=None, b: int = 0, a: int = 0,
                 charset: str = CHARSET_B, years=None):
    """Полный пайплайн File 2 для одного логина."""
    if years is None:
        years = []
    stem = strip_login(login.lower(), sb, sa, b, a)
    if not stem:
        return
    for r in translit_variants(stem):
        forms = [r]
        cap = r[:1].upper() + r[1:]
        if cap != r:
            forms.append(cap)
        for form in forms:
            s = to_en_layout(form)
            yield from append_tails(s, charset, years)


# ── IO layer ────────────────────────────────────────────────────────────────

def load_config(conf_path: Path) -> dict:
    if not conf_path.exists():
        sys.exit(f"Config not found: {conf_path}\nRun: nxc_collector --workspace-setup")
    cfg = ConfigParser()
    cfg.read(str(conf_path))
    if "collector" not in cfg:
        sys.exit(f"Missing [collector] section in {conf_path}")
    c = cfg["collector"]
    server = c.get("server", "http://192.168.0.1").rstrip("/")
    if not server.startswith(("http://", "https://")):
        server = f"http://{server}"
    port = c.get("port", "322").strip()
    if port and not re.search(r":\d+$", server):
        server = f"{server}:{port}"
    return {
        "server": server,
        "password": c.get("password", "StrongPassword123"),
        "operator": c.get("operator", "Operator"),
        "workspace": c.get("workspace", "default"),
    }


def _token(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def resolve_workspace(server: str, token: str, ws_name: str):
    req = urllib.request.Request(f"{server}/api/workspaces", headers={"X-Auth-Token": token})
    with urllib.request.urlopen(req, timeout=10) as resp:
        ws_list = json.loads(resp.read())
    ws = next((w for w in ws_list if w["name"] == ws_name), None)
    if ws is None:
        sys.exit(f"Workspace '{ws_name}' not found on server")
    return ws["id"]


def fetch_all(server: str, token: str, path: str, params: dict) -> list:
    all_rows, page = [], 1
    while True:
        p = {**params, "page": page, "limit": 2000}
        url = f"{server}{path}?{urllib.parse.urlencode(p)}"
        req = urllib.request.Request(url, headers={"X-Auth-Token": token})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        rows = data.get("rows", [])
        all_rows.extend(rows)
        total = data.get("total", len(all_rows))
        if len(all_rows) >= total or not rows:
            break
        page += 1
    return all_rows


def read_offline_logins(path: str) -> list:
    """Логины из локального файла (по одному на строку) — для режима --offline-file.
    Пустые/пробельные строки пропускаются, пробелы по краям срезаются. API не трогается."""
    with open(path, encoding="utf-8", errors="replace") as f:
        return [line.strip() for line in f if line.strip()]


def collect_logins(creds: list, custom: list, dpapi: list) -> list:
    out: set = set()
    for row in list(creds) + list(custom) + list(dpapi):
        u = row.get("username") or ""
        if u and not is_skip_user(u):
            out.add(u)
    return sorted(out)


def _parse_args(argv=None):
    ap = argparse.ArgumentParser(
        prog="dicgenerat",
        description="Генератор словарей для credential-спрея (сервер PenHub).")
    ap.add_argument("-ws", "--workspace", help="Override воркспейса из конфига")
    ap.add_argument("-o", "--out", default=".", help="Каталог вывода (default: cwd)")
    ap.add_argument("-sb", default=None, help="Срезать первый слева SEP и всё до него")
    ap.add_argument("-sa", default=None, help="Срезать последний SEP и всё после него")
    ap.add_argument("-b", type=int, default=0, help="Срезать ровно N символов спереди")
    ap.add_argument("-a", type=int, default=0, help="Срезать ровно N символов сзади")
    ap.add_argument("--offline-file", default=None,
                    help="Взять логины из локального файла (по одному на строку), без обращения к API")
    return ap.parse_args(argv)


def main(argv=None) -> int:
    args = _parse_args(argv)

    if args.offline_file:
        # Offline: логины из файла, к API не обращаемся (конфиг/сервер не нужны).
        logins = read_offline_logins(args.offline_file)
        ws_name = args.workspace or Path(args.offline_file).stem
        creds = [{"username": u} for u in logins]
        custom, dpapi = [], []
    else:
        config = load_config(CONF_FILE)
        ws_name = args.workspace or config["workspace"]
        token = _token(config["password"])
        server = config["server"]
        ws_id = resolve_workspace(server, token, ws_name)
        creds = fetch_all(server, token, "/api/credentials",
                          {"workspace_id": ws_id, "hide_guest": "false"})
        custom = fetch_all(server, token, "/api/custom_creds", {"workspace_id": ws_id})
        dpapi = fetch_all(server, token, "/api/dpapi", {"workspace_id": ws_id})

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    # File 1 — base (small, in-memory set)
    base = build_base(creds, custom, dpapi)
    base_path = out_dir / f"{ws_name}_base.txt"
    base_path.write_text("\n".join(base) + ("\n" if base else ""), encoding="utf-8")

    # File 2 — mutated (stream to temp, then external sort -u)
    logins = collect_logins(creds, custom, dpapi)
    years = years_since(datetime.date.today().year)
    mut_path = out_dir / f"{ws_name}_mutated.txt"
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False,
                                     dir=str(out_dir), suffix=".tmp") as tf:
        tmp_name = tf.name
        for login in logins:
            for cand in mutate_login(login, args.sb, args.sa, args.b, args.a,
                                     CHARSET_B, years):
                tf.write(cand + "\n")
    try:
        subprocess.run(["sort", "-u", tmp_name, "-o", str(mut_path)],
                       env={**os.environ, "LC_ALL": "C"}, check=True)
    finally:
        os.unlink(tmp_name)

    def _count(p):
        with open(p, encoding="utf-8") as f:
            return sum(1 for _ in f)

    print(f"[+] {base_path}  ({len(base)} строк)")
    print(f"[+] {mut_path}  ({_count(mut_path)} строк)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
