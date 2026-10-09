#!/usr/bin/env python3
"""nidhunt helper: build vocabularies and verify NIDs.

This is the reference implementation of the PS5 NID hash and a few conveniences
around it. It bundles no symbol data; you point it at your own symbol lists.

Subcommands:
  nid   NAME...                 print the NID for each symbol name
  check NAME NID                exit 0 if NAME hashes to NID, else 1
  words --symbols FILE ...      extract CamelCase words to build a vocab file
                                (--rank orders by frequency, most common first)
  positions --symbols FILE --prefix P --out STEM
                                per-position ranked word lists for grammar mode

Examples:
  python tools/vocab.py nid sceNpSessionSignalingCreateContext
  python tools/vocab.py check sceNpSessionSignalingCreateContext GtuZGmN-tKw
  python tools/vocab.py words --symbols known_symbols.txt --prefix sceVideoOut --rank > vocab.txt
  python tools/vocab.py positions --symbols known_symbols.txt --prefix sceVideoOut --out vo
  #   -> vo_1.txt, vo_2.txt, ...  then:  nidhunt -t t.txt -p sceVideoOut -s vo_1.txt -s vo_2.txt

Ranking by frequency, combined with nidhunt's early-exit once all targets are
found, tries the most likely names first and stops as soon as they are hit.
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


def split_words(name, prefix):
    """Words of `name` after `prefix`, in order (empty if prefix doesn't match)."""
    if not name.startswith(prefix):
        return []
    return _WORD.findall(name[len(prefix):].split("_")[0])


def words_from(names, prefixes, rank=False):
    """Distinct words across names. Sorted alphabetically, or, with rank=True,
    by descending frequency (most common first) so a search tries likely words
    first — which, with nidhunt's early-exit, finds hits sooner."""
    from collections import Counter
    counts = Counter()
    for n in names:
        for pfx in prefixes:
            counts.update(split_words(n, pfx))
    if rank:
        return [w for w, _ in counts.most_common()]
    return sorted(counts)


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
    p_w.add_argument("--rank", action="store_true", help="order by frequency (most common first) instead of alphabetically")

    p_p = sub.add_parser("positions",
                         help="per-position ranked word lists for grammar mode (a Markov-by-position model)")
    p_p.add_argument("--symbols", action="append", required=True, help="symbol list file (repeatable)")
    p_p.add_argument("--prefix", required=True, help="common prefix to strip, e.g. sceVideoOut")
    p_p.add_argument("--out", required=True, help="output path stem; writes <stem>_1.txt, <stem>_2.txt, ...")
    p_p.add_argument("--max-slots", type=int, default=4, help="number of positions to emit (default 4)")

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
        for w in words_from(names, a.prefix or [""], rank=a.rank):
            print(w)
    elif a.cmd == "positions":
        from collections import Counter
        names = read_symbols(a.symbols)
        # Rank words by frequency at each position after the prefix: position 0
        # is the first word, position 1 the second, and so on. This is a simple
        # per-position (Markov-by-position) model of how names in this library
        # are built. Feed the files to grammar mode: -s <stem>_1.txt -s ...
        per_pos = [Counter() for _ in range(a.max_slots)]
        for n in names:
            ws = split_words(n, a.prefix)
            for i, w in enumerate(ws[:a.max_slots]):
                per_pos[i][w] += 1
        written = 0
        for i, counts in enumerate(per_pos):
            if not counts:
                break
            path = f"{a.out}_{i + 1}.txt"
            with open(path, "w", encoding="utf-8") as f:
                for w, _ in counts.most_common():
                    f.write(w + "\n")
            print(f"wrote {path} ({len(counts)} words)", file=sys.stderr)
            written += 1
        if not written:
            print(f"no symbols matched prefix {a.prefix!r}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
