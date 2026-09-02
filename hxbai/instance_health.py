from __future__ import annotations

import re

_APP_FATAL = re.compile(
    r"Uncaught\s+(?:mysqli_sql_exception|PDOException|PDOException|RuntimeException|Error)"
    r"[^\n]{0,160}?in\s+/[\w./-]+\.(?:php|py|js|rb|go|java)", re.I)
_INJECTED_SQL_ERROR = re.compile(
    r"you have an error in your sql syntax|"
    r"xpath syntax error|"
    r"syntax to use near|"
    r"check the manual[^\"\n]{0,60}corresponds|"
    r"unclosed quotation|"
    r"unterminated string", re.I)
_MISSING_TABLE = re.compile(
    r"(?:Table|table)\s+'?([\w`]+\.[\w`]+)'?\s+doesn't exist", re.I)
_DB_DOWN = re.compile(
    r"SQLSTATE\[HY000\]\s*\[2002\]|"
    r"Can't connect to (?:local )?MySQL|"
    r"connection refused[^\"\n]{0,40}(?:mysql|postgres|redis|3306|5432|6379)|"
    r"(?:mysql|postgres|redis)[^\"\n]{0,30}connection refused", re.I)
_BACKEND_ABSENT = re.compile(
    r"no\s+(?:mysql|postgres|redis|mariadb|mongodb)\s+on\s+any\s+port", re.I)
_DB_UNREACHABLE = re.compile(
    r"mysqli::__construct\(\)[^\n]{0,100}?(?:getaddrinfo|php_network_getaddresses)"
    r"|php_network_getaddresses[^\n]{0,80}?getaddrinfo"
    r"|(?:PDO|pgsql|pg_connect)[^\n]{0,60}?(?:getaddrinfo failed|php_network_getaddresses)", re.I)


def scan_session(text: str) -> list:
    if not text:
        return []
    hits: list = []
    named_tables: list = []
    try:
        for m in _APP_FATAL.finditer(text):
            frag = m.group(0)
            if _INJECTED_SQL_ERROR.search(frag):
                continue
            tm = _MISSING_TABLE.search(frag)
            if tm:
                named_tables.append(tm.group(1).lower())
            else:
                hits.append("app-fatal")
        if len(set(named_tables)) == 1:
            hits.append(f"missing-table:{named_tables[0]}")
        for name, rx in (("db-down", _DB_DOWN), ("backend-absent", _BACKEND_ABSENT),
                         ("db-unreachable", _DB_UNREACHABLE)):
            if rx.search(text):
                hits.append(name)
    except Exception:
        return []
    return sorted(set(hits))


class BrokenInstanceTracker:

    def __init__(self, corroboration: int = 2):
        self.corroboration = max(1, int(corroboration))
        self._seen: dict = {}

    def feed(self, code: str, signatures: list) -> None:
        by_sig = self._seen.setdefault(code, {})
        for name in signatures or []:
            by_sig[name] = by_sig.get(name, 0) + 1

    def verdict(self, code: str):
        by_sig = self._seen.get(code) or {}
        for name, n in by_sig.items():
            if n >= self.corroboration:
                return f"{name}x{n}"
        return None

    def has_signals(self, code: str) -> bool:
        return bool(self._seen.get(code))

    def reset(self, code: str) -> None:
        self._seen.pop(code, None)
