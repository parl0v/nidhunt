# nidhunt

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
accepted into those projects' review queues (AnyPS5 #2319, sce_symbols #22).

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

Requires a C++17 compiler. The GPU backend additionally needs an OpenCL loader
(any GPU vendor's; the headers are bundled under `src/CL`).

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
| `--self-test` | verify the hashing against the known NID and exit |
| `--list-devices` | list OpenCL GPUs and exit |
| `-h, --help` | usage |

### Input file formats

All three input kinds are plain text, one token per line; blank lines and lines
starting with `#` are ignored. The same files work on both backends.

* **vocab / slot** — one word per line, in natural CamelCase (`Create`,
  `Signaling`, `Context`).
* **suffixes** — one suffix per line (e.g. a version tag like `_0100`, or a
  variant like `Ex`). The no-suffix case is always included.
* **targets** — one 11-character NID per line. Anything after the NID (and
  whitespace) is a free-text annotation that is echoed back on a hit, so you can
  keep the library name or import notes alongside each NID.

See the `examples/` directory for samples.

### Output

Hits go to stdout, one per line; progress and statistics go to stderr.

```
HIT <nid> <name>   <annotation from the targets file, if any>
```

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
```

It accepts plain names, `'name': '...'`-style lines, or `<nid> <name>` lines, so
you can point it at exports you have already mapped. It bundles no data of its
own.

## Performance

Measured on an i5-14400F (16 threads) and an RTX 4060:

| backend | throughput |
|---|---|
| GPU (`nidhunt-gpu --backend gpu`, RTX 4060, OpenCL) | ~1.8–2.7 G names/s |
| CPU (`nidhunt`, SHA-NI, 16 threads) | ~0.2 G names/s |
| CPU (portable scalar fallback, no SHA-NI) | ~50 M names/s |

Throughput depends on the candidate shape: names that fit one 64-byte SHA-1
block (≤ 39 characters, the common case) hash at roughly double the rate of
longer names that need two, and more slots mean more mixed-radix divisions per
candidate on the GPU.

The CPU backend uses the x86 **SHA-NI** instructions when the CPU has them
(detected at run time) and falls back to a portable scalar SHA-1 otherwise, so
it builds and runs on any target.

The hot paths already apply the cheap wins: the GPU keeps its per-slot lookup
tables in constant memory, skips the divide on the final slot, and zeroes only
the SHA-1 padding gap; the CPU hashes in place (no per-candidate message copy)
and realigns/​de-vectorizes the worker so SHA-NI runs safely on MinGW threads.

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

### Ideas for going faster / smarter

These are deliberately not implemented yet; the current code favours one clear,
general code path over peak speed. Rough expected gains:

* **Specialize the hot loop per fixed depth.** The generic per-slot indirection
  (pointer-chase into each slot's word list every candidate) costs maybe 1.5× on
  both backends versus a shape fixed at compile time. Emit a specialized kernel
  for the common depths.
* **Reuse the invariant head of the name.** Across one odometer sweep only the
  last slot changes; rebuilding just the tail (and re-running only the final
  SHA-1 block) avoids redundant work for long names.
* **Overlap GPU batches.** The GPU currently reads the hit counter back after
  every batch, stalling the pipeline. Double-buffering the hit buffer and only
  reading it when the atomic counter is non-zero would hide that latency.
* **Smarter candidate order.** Weight words by their frequency in known symbols
  and enumerate high-probability names first; mine affix statistics (common
  prefixes, verb/object pairings, version-suffix patterns) from an existing
  symbol set to shrink the realistic space.
* **Markov / learned word models.** Score candidate names by a model trained on
  known PS5 symbol names and cut off low-probability branches early.

## Contributing recovered names

Names found with nidhunt are hash-verified and can be proposed to the relevant
project — e.g. [AnyPS5](https://github.com/boykopovar/AnyPS5) or
[sce_symbols](https://github.com/zecoxao/sce_symbols). Follow each project's own
contribution process. Only submit names you have verified, and remember a
hash match is a *candidate*: a name can collide or simply be the wrong spelling
of the real one, so sanity-check it against the surrounding API before relying
on it.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).

The OpenCL headers bundled under `src/CL/` are from the Khronos Group and are
distributed under their own Apache-2.0 license (see the notices in those files);
they are included only to make the GPU build self-contained.
