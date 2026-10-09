#!/usr/bin/env python3
"""nidhunt helper: build vocabularies and verify NIDs.

This is the reference implementation of the PS5 NID hash and a few conveniences
around it. It bundles no symbol data; you point it at your own symbol lists.

Subcommands:
  nid   NAME...                 print the NID for each symbol name
  check NAME NID                exit 0 if NAME hashes to NID, else 1
  words --symbols FILE ...      extract CamelCase words to build a vocab file

Examples:
  python tools/vocab.py nid sceNpSessionSignalingCreateContext
  python tools/vocab.py check sceNpSessionSignalingCreateContext GtuZGmN-tKw
  python tools/vocab.py words --symbols known_symbols.txt --prefix sceVideoOut > vocab.txt
"""
import argparse
import hashlib
import re
import sys

# Public, well-known PS5 NID salt (not a secret, not a key).
SALT = bytes([0x51, 0x8D, 0x64, 0xA6, 0x35, 0xDE, 0xD8, 0xC1,
              0xE6, 0xB0, 0x39, 0xB1, 0xC3, 0xE5, 0x52, 0x30])
CS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-"


def nid(name: str) -> str:
    """NID = first 8 bytes of SHA1(name + SALT) read little-endian, base64(CS)-encoded."""
    d = hashlib.sha1(name.encode() + SALT).digest()
    v = int.from_bytes(d[:8], "little")
    out = [CS[(v >> (58 - 6 * i)) & 0x3F] for i in range(10)]
    out.append(CS[(v & 0xF) << 2])
    return "".join(out)


# Split a symbol's trailing part into natural CamelCase / digit words.
_WORD = re.compile(r"[A-Z][a-z0-9]+|[A-Z]+(?=[A-Z]|\b|_|\d)|[A-Z]+|\d+")


def words_from(names, prefixes):
    out = set()
    for n in names:
        for pfx in prefixes:
            if not n.startswith(pfx):
                continue
            rest = n[len(pfx):].split("_")[0]
            out.update(_WORD.findall(rest))
    return sorted(out)


def read_symbols(paths):
    """Read symbol names from files. Accepts plain names or lines containing
    'name': '...', "name": "...", or an 11-char NID followed by the name."""
    names = set()
    for p in paths:
        with open(p, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                m = re.search(r"['\"]name['\"]\s*:\s*['\"]([^'\"]+)['\"]", line)
                if m:
                    names.add(m.group(1))
                    continue
                toks = line.split()
                # "<nid> <name> ..." style (e.g. a targets/contrib file)
                if len(toks) >= 2 and len(toks[0]) == 11:
                    names.add(toks[1])
                else:
                    names.add(toks[0] if toks else line)
    return names


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_nid = sub.add_parser("nid", help="print the NID for each symbol name")
    p_nid.add_argument("names", nargs="+")

    p_chk = sub.add_parser("check", help="verify NAME hashes to NID")
    p_chk.add_argument("name")
    p_chk.add_argument("expected_nid")

    p_w = sub.add_parser("words", help="extract CamelCase words from symbol files")
    p_w.add_argument("--symbols", action="append", required=True, help="symbol list file (repeatable)")
    p_w.add_argument("--prefix", action="append", default=[], help="only names with this prefix (repeatable; default: all)")

    a = ap.parse_args()

    # Sanity check the implementation on every run.
    assert nid("sceNpSessionSignalingCreateContext") == "GtuZGmN-tKw", "NID implementation mismatch"

    if a.cmd == "nid":
        for n in a.names:
            print(nid(n), n)
    elif a.cmd == "check":
        got = nid(a.name)
        if got == a.expected_nid:
            print(f"OK {got} {a.name}")
            return 0
        print(f"MISMATCH {a.name}: got {got}, expected {a.expected_nid}", file=sys.stderr)
        return 1
    elif a.cmd == "words":
        names = read_symbols(a.symbols)
        for w in words_from(names, a.prefix or [""]):
            print(w)
    return 0


if __name__ == "__main__":
    sys.exit(main())
