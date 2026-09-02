#!/usr/bin/env python3
import argparse
import sys

try:
    from datetime import datetime
    _CUR_YEAR = datetime.now().year
except Exception:
    _CUR_YEAR = 2026

_GENERIC_PW = [
    "admin", "admin123", "admin@123", "Admin@123", "admin888", "admin@888",
    "root", "root123", "toor", "123456", "12345678", "123456789", "password",
    "Password", "Password1", "Passw0rd", "P@ssw0rd", "P@ssword123", "pass123",
    "1qaz@WSX", "1qaz2wsx", "1qaz!QAZ", "qazwsx", "qwe123", "qwer1234", "abc123",
    "abc@123", "a123456", "changeme", "letmein", "test123", "guest", "welcome",
]
_GENERIC_USERS = [
    "admin", "administrator", "root", "manager", "operator", "ops", "oa",
    "it", "itadmin", "sysadmin", "system", "deploy", "test", "guest", "ftpuser",
    "user", "webadmin", "backup",
]


def _seps():
    return ["@", "", ".", "_", "@@", "#", "!", "-"]


def _year_window(year):
    return [str(y) for y in range(year - 4, year + 2)]


def _tails(year):
    t = ["123", "1234", "123456", "@123", "@1234", "@123456", "888", "666",
         "2023", "admin", "abc"]
    for y in _year_window(year):
        t.append(y)
    return t


def _cases(word):
    w = word.strip()
    if not w:
        return []
    out = {w.lower(), w.upper(), w.capitalize(), w}
    return [x for x in out if x]


def gen_passwords(products, names, year):
    pw = []
    seen = set()

    def add(p):
        if p and p not in seen:
            seen.add(p)
            pw.append(p)

    stems = []
    for grp in (products, names):
        for raw in grp:
            for c in _cases(raw):
                stems.append(c)
    for s in stems:
        add(s)
        for sep in _seps():
            for tail in _tails(year):
                add(f"{s}{sep}{tail}")
        add(f"{s}123")
        add(f"{s}@2023")
        add(f"{s}#2023")
    for g in _GENERIC_PW:
        add(g)
    for sep in _seps():
        for y in _year_window(year):
            add(f"Admin{sep}{y}")
            add(f"admin{sep}{y}")
    return pw


def gen_users(products, names):
    users = []
    seen = set()

    def add(u):
        if u and u not in seen:
            seen.add(u)
            users.append(u)

    for grp in (products, names):
        for raw in grp:
            for c in _cases(raw):
                add(c)
    for g in _GENERIC_USERS:
        add(g)
    return users


def _parse_list(spec):
    if not spec:
        return []
    return [x.strip() for x in spec.split(",") if x.strip()]


def main():
    ap = argparse.ArgumentParser(description="default/product-derived credential family generator")
    ap.add_argument("--products", default="", help="product/vendor keywords seen on target, comma-separated (e.g. weaver,seeyon)")
    ap.add_argument("--names", default="", help="company/system name keywords, comma-separated")
    ap.add_argument("--year", type=int, default=_CUR_YEAR, help=f"anchor year (default {_CUR_YEAR}); a +-window is generated")
    ap.add_argument("--pw-out", default="", help="write passwords to this file")
    ap.add_argument("--user-out", default="", help="write usernames to this file")
    a = ap.parse_args()

    products = _parse_list(a.products)
    names = _parse_list(a.names)
    if not products and not names:
        sys.stderr.write("give at least --products or --names (the keywords you saw on the target)\n")
        return 2

    pws = gen_passwords(products, names, a.year)
    users = gen_users(products, names)

    if a.pw_out:
        open(a.pw_out, "w", encoding="utf-8").write("\n".join(pws) + "\n")
    if a.user_out:
        open(a.user_out, "w", encoding="utf-8").write("\n".join(users) + "\n")
    if not a.pw_out and not a.user_out:
        sys.stdout.write("\n".join(pws) + "\n### USERS\n" + "\n".join(users) + "\n")
    sys.stderr.write(f"[defaultpass] {len(pws)} passwords, {len(users)} usernames "
                     f"(year window {a.year-4}..{a.year+1})\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
