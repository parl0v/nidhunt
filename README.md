# nidhunt

[![ci](https://github.com/parl0v/nidhunt/actions/workflows/ci.yml/badge.svg)](https://github.com/parl0v/nidhunt/actions/workflows/ci.yml)

Recover PlayStation 5 system-library symbol **names** from their **NID** hashes,
for open-source emulator and homebrew work.

PS5 libraries do not export functions by name. Each export is identified by an
11-character **NID**, computed from the function's name. Projects that
reimplement these libraries — emulators such as
[AnyPS5](https://github.com/boykopovar/AnyPS5) and the community symbol database
[zecoxao/sce_symbols](https://github.com/zecoxao/sce_symbols) — can only
implement a function once its NID is mapped back to a plausible name. Many NIDs
that games import are still unnamed.

nidhunt generates candidate names from word lists and checks their hashes
against a set of target NIDs. A match is **hash-verified**: the recovered name
provably hashes to the target, so names found this way can be contributed back
to those projects with confidence. Names recovered with this approach have been
submitted to those projects' review queues
([AnyPS5 #2319](https://github.com/boykopovar/AnyPS5/pull/2319),
[sce_symbols #22](https://github.com/zecoxao/sce_symbols/pull/22)).

nidhunt only hashes **function names**. It does not touch keys, passwords, or
copy protection, and ships with no symbol data — you supply your own word lists
and target NIDs.

## What a NID is

For a symbol name `N`:

```
digest = SHA1( N + SALT )          # SALT is a fixed, public 16-byte value
key    = first 8 bytes of digest, read little-endian
NID    = key, encoded as 11 chars with the alphabet
         A-Za-z0-9+-   ( '-' takes the place of base64's '/' )
```

`SALT` is a well-known constant shipped in the PS5 system libraries; it is not a
secret and not a cryptographic key. The hash is one-way, so a name cannot be
derived from a NID directly — it has to be guessed and checked. That is what
nidhunt does, quickly, over structured candidate names.

Canonical reference (used as the built-in self-test):

```
sceNpSessionSignalingCreateContext  ->  GtuZGmN-tKw
```

## Building

Requires a C++17 **GCC or Clang** compiler (the code uses GNU-style intrinsics
and attributes; on Windows use MinGW-w64 GCC, not MSVC). The GPU backend
additionally needs an OpenCL loader (any GPU vendor's; the headers are bundled
under `src/CL`). On non-x86 or non-GNU targets it builds with a portable scalar
SHA-1 and no SHA-NI.

**Windows (MinGW / GCC):**

```bash
.\build.ps1          # PowerShell:  nidhunt.exe + nidhunt-gpu.exe if OpenCL is present
```

**Linux / macOS / Git Bash:**

```bash
./build.sh           # nidhunt + nidhunt-gpu if OpenCL is present
./build.sh cpu       # CPU binary only
./build.sh gpu       # require the GPU build, fail if OpenCL is missing
```

Or with CMake:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build
```

The build produces up to two binaries:

* **`nidhunt`** — CPU backend only, no external dependencies.
* **`nidhunt-gpu`** — CPU *and* GPU backends. Use `--backend gpu` to select the
  GPU; it also runs CPU searches, so you only need this one if you have OpenCL.

## Usage

```
nidhunt -t TARGETS (-v VOCAB -d DEPTH | -s SLOT [-s SLOT ...]) [options]
```

A candidate name is

```
prefix + slot0 + slot1 + ... (+ suffix)
```

and a hit is reported when `first8(SHA1(name + SALT))` equals one of the target
NIDs. There are two ways to describe the candidate space:

**Combinator** — names of 1..N words, each word drawn from one vocabulary:

```bash
nidhunt -t targets.txt -p sceVideoOut -v vocab.txt -d 3 -S suffixes.txt
#   sceVideoOut + {1..3 words from vocab.txt} + {optional suffix}
```

**Grammar** — one word list per position, in order (folds in what the old
`clgram` prototype did):

```bash
nidhunt -t targets.txt -p sce -s verbs.txt -s objects.txt -S suffixes.txt
#   sce + {one verb} + {one object} + {optional suffix}
```

### Options

| option | meaning |
|---|---|
| `-t, --targets FILE` | NIDs to search for (required) |
| `-v, --vocab FILE` + `-d, --depth N` | combinator: 1..N words from `FILE` |
| `-s, --slot FILE` | grammar: one word list per position (repeatable) |
| `-p, --prefix STR` | fixed leading text, e.g. `sceVideoOut` |
| `-S, --suffix FILE` | suffix list; the empty suffix is always tried too |
| `--backend cpu\|gpu\|auto` | default `auto` (GPU if built and present, else CPU) |
| `--threads N` | CPU worker threads (default: all cores) |
| `--device N` | OpenCL GPU index to use (see `--list-devices`; default 0) |
| `--self-test` | verify the hashing against the known NID and exit |
| `--list-devices` | list OpenCL GPUs and exit |
| `-h, --help` | usage |

Candidate names longer than 100 characters are skipped (over-long vocab words
and an over-long `--prefix` are rejected at load). Use `--vocab`/`--depth` **or**
`--slot`, not both.

### Input file formats

All three input kinds are plain text, one token per line; blank lines and lines
starting with `#` are ignored; duplicate lines are dropped (keeping order). A
path that cannot be opened is a fatal error. The same files work on both backends.

* **vocab / slot** — one word per line, in natural CamelCase (`Create`,
  `Signaling`, `Context`).
* **suffixes** — one suffix per line (e.g. a version tag like `_0100`, or a
  variant like `Ex`). The no-suffix case is always included.
* **targets** — one 11-character NID per line. Anything after the NID (and
  whitespace) is a free-text annotation that is echoed back on a hit, so you can
  keep the library name or import notes alongside each NID.

See the `examples/` directory for samples.

### Output

Hits go to **stdout**, one per line, plain and script-friendly:

```
HIT <nid> <name>   <annotation from the targets file, if any>
```

Everything else — a banner, a live progress bar (percentage, candidates
done/total, rate, elapsed, ETA, hits found, current plan), and a final summary
that lists any **unfound** targets — goes to **stderr**, so piping stdout stays
clean. The bar and colors appear only on a terminal; set `NO_COLOR` to disable
colors, and redirect stderr to drop the bar entirely.

## Verifying a hit

Every hit is already hash-checked by nidhunt (and GPU hits are re-checked on the
CPU before printing). To confirm one independently, or to check a name by hand,
use the reference implementation in `tools/vocab.py`:

```bash
python tools/vocab.py nid   sceNpSessionSignalingCreateContext   # -> GtuZGmN-tKw <name>
python tools/vocab.py check sceNpSessionSignalingCreateContext GtuZGmN-tKw   # exit 0 if it matches
```

Any independent SHA-1 implementation reproduces it:

```python
import hashlib
SALT = bytes([0x51,0x8D,0x64,0xA6,0x35,0xDE,0xD8,0xC1,0xE6,0xB0,0x39,0xB1,0xC3,0xE5,0x52,0x30])
hashlib.sha1("sceNpSessionSignalingCreateContext".encode() + SALT).digest()[:8]
# the first 8 bytes, encoded, are the NID GtuZGmN-tKw
```

## Building word lists

`tools/vocab.py words` extracts CamelCase words from a list of symbols you
already know (for the same library you are attacking), to seed a vocabulary:

```bash
python tools/vocab.py words --symbols known_symbols.txt --prefix sceVideoOut > vocab.txt
python tools/vocab.py words --symbols known_symbols.txt --prefix sceVideoOut --rank > vocab.txt  # frequency-ordered
python tools/vocab.py positions --symbols known_symbols.txt --prefix sceVideoOut --out vo        # vo_1.txt, vo_2.txt, ...
```

It accepts plain names, `'name': '...'`-style lines, or `<nid> <name>` lines, so
you can point it at exports you have already mapped. It bundles no data of its
own. `--rank` and `positions` order the output so likely names are tried first;
see [Smarter searching](#smarter-searching).

## Performance

Measured on an i5-14400F (16 threads) and an RTX 4060 (driver 616.56), on a
depth-3 combinator over a ~2,200-word vocabulary with an `sceVideoOut` prefix
(realistic one-block names), no targets hit:

| backend | throughput |
|---|---|
| GPU (`nidhunt-gpu --backend gpu`, RTX 4060, OpenCL) | ~3.4–4.0 G names/s |
| CPU (`nidhunt`, SHA-NI, 16 threads) | ~0.3 G names/s |
| CPU (portable scalar fallback, no SHA-NI) | ~50 M names/s |

Throughput depends on the candidate shape: names that fit one 64-byte SHA-1
block (≤ 39 characters, the common case) hash faster than longer names that need
two blocks.

The CPU backend uses the x86 **SHA-NI** instructions when the CPU has them
(detected at run time) and falls back to a portable scalar SHA-1 otherwise, so
it builds and runs on any target.

The hot paths are tuned:

* **GPU** generates a kernel specialized to each plan shape with the slot counts
  baked in as literals — the slot loop unrolls and every mixed-radix divide
  becomes a constant-division magic multiply. Several batches stay in flight
  before a sync to hide read-back latency (bounded so no GPU-busy window trips
  the Windows watchdog).
* **CPU** hashes in place (no per-candidate message copy), reuses the invariant
  head of the name across the innermost slot (only the tail + hash is redone),
  parallelizes over the whole head space (so every thread gets work regardless
  of which slot is largest), rejects non-matches with a one-instruction bloom
  filter before the exact check, and force-aligns / de-vectorizes the worker so
  SHA-NI runs safely on MinGW threads.
* **Both** stop as soon as every target NID has been found, so searching for a
  handful of NIDs finishes the moment they turn up instead of scanning the whole
  space. Order the vocabulary with `tools/vocab.py ... --rank` to try the most
  likely names first and hit that early-exit sooner.

### Search-space sizing

Cost is the product of the slot sizes, so it grows fast with depth:

* a 500-word vocab at depth 3 is 1.25 × 10⁸ candidates — well under a second on
  the GPU;
* the same vocab at depth 4 is 6.25 × 10¹⁰ — about a minute on the GPU, far
  longer on the CPU.

Keep vocabularies tight and lean on `--prefix` and the grammar mode to cut the
space. Deriving the vocabulary from known symbols in the *same* library (via
`tools/vocab.py words`) is usually far more productive than a bigger generic
list.

### Smarter searching

Beyond raw throughput, shrink and reorder the space so the names you want turn
up first (and the early-exit ends the run):

* **Order by frequency.** `tools/vocab.py words --symbols known.txt --prefix P
  --rank` emits the vocabulary most-common-word-first, learned from symbols you
  already know in the same library.
* **Per-position (Markov-by-position) grammar.** `tools/vocab.py positions
  --symbols known.txt --prefix P --out vo` writes `vo_1.txt`, `vo_2.txt`, … —
  each position's words ranked by how often they appear *there*. Feed them to
  grammar mode (`-s vo_1.txt -s vo_2.txt …`) to enumerate the realistic names
  for that library first.
* **Keep the space tight.** Lean on `--prefix` and grammar mode; a vocabulary
  derived from the same library beats a bigger generic list.

### Further ideas (not implemented)

* A full word-level Markov model with best-first enumeration (priority queue)
  rather than dense index order — higher hit-rate per candidate, but it gives up
  the GPU's dense-index parallelism, so it suits a CPU pre-pass.
* SHA-1 midstate reuse for names longer than one block (precompute the hash of
  the invariant leading block). PS5 names are usually one block, so the payoff
  is small today.

## Contributing recovered names

Names found with nidhunt are hash-verified and can be proposed to the relevant
project — e.g. [AnyPS5](https://github.com/boykopovar/AnyPS5) or
[sce_symbols](https://github.com/zecoxao/sce_symbols). Follow each project's own
contribution process. Only submit names you have verified, and remember a
hash match is a *candidate*: a name can collide or simply be the wrong spelling
of the real one, so sanity-check it against the surrounding API before relying
on it.

A NID is a 64-bit truncated hash, so collisions are possible but rare: a random
name matches a given NID with probability ≈ 1 / 2⁶⁴. Over a large run — say
10¹³ candidates against 40 target NIDs — the expected number of *spurious*
matches is about `1e13 × 40 / 2⁶⁴ ≈ 0.002%`. In practice a hit is almost
certainly the real name, but a plausible, API-consistent spelling is the real
confirmation.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).

The OpenCL headers bundled under `src/CL/` are from the Khronos Group and are
distributed under their own Apache-2.0 license (see the notices in those files);
they are included only to make the GPU build self-contained.
