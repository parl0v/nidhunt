// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Josip Parlov (parl0v)
// nidhunt - recover PS5 symbol names from their NID hashes by generating and
// hash-checking candidate names. See README.md for background and usage.
//
// Build CPU-only:   g++ -O3 -std=c++17 -pthread src/nidhunt.cpp -o nidhunt
// Build with GPU:   add  -DNIDHUNT_OPENCL -Isrc  and link OpenCL.
//
// This tool hashes candidate *function names* only. The salt is the public,
// well-known PS5 NID salt; nothing here touches keys, passwords, or protection.
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "common.h"

#ifdef _WIN32
#include <io.h>
static bool fd_is_tty(FILE* f) { return _isatty(_fileno(f)) != 0; }
#else
#include <unistd.h>
static bool fd_is_tty(FILE* f) { return isatty(fileno(f)) != 0; }
#endif

#ifdef NIDHUNT_OPENCL
#define CL_TARGET_OPENCL_VERSION 120
#include <CL/cl.h>
#include "cl_kernel.h"
#endif

// The SHA-NI worker needs its stack realigned and auto-vectorization off only on
// Windows + GCC, where std::thread stacks are not 16-byte aligned. Elsewhere
// (Linux/macOS GCC or Clang) stacks are ABI-aligned, so these attributes are
// unnecessary; Clang does not implement optimize() and would warn, so they are
// gated off there.
#if defined(_WIN32) && defined(__GNUC__) && !defined(__clang__) && (defined(__x86_64__) || defined(__i386__))
#define NIDHUNT_WORKER_ATTR __attribute__((force_align_arg_pointer, optimize("no-tree-vectorize", "no-tree-slp-vectorize")))
#else
#define NIDHUNT_WORKER_ATTR
#endif
#if defined(__GNUC__) || defined(__clang__)
#define NIDHUNT_AINLINE inline __attribute__((always_inline))
#else
#define NIDHUNT_AINLINE inline
#endif

using namespace nidhunt;

namespace {

struct Config {
    std::string targets_path, vocab_path, suffix_path, prefix, backend = "auto";
    std::vector<std::string> slot_paths;
    int depth = 0;
    int threads = 0;
    int device = -1;  // OpenCL GPU index, -1 = first
    bool self_test = false, list_devices = false, help = false;
};

// Terminal styling. stdout stays plain (machine-readable HIT lines); stderr
// carries the colored banner, live progress bar, and summary. Colors only when
// the stream is a TTY and NO_COLOR is unset.
struct Ui {
    bool out_tty = false, err_tty = false, err_color = false;
    std::string e(const char* code) const { return err_color ? code : ""; }
    static Ui detect() {
        bool no = std::getenv("NO_COLOR") != nullptr;
        Ui u;
        u.out_tty = fd_is_tty(stdout);
        u.err_tty = fd_is_tty(stderr);
        u.err_color = u.err_tty && !no;
        return u;
    }
};
namespace ansi {
constexpr const char* RST = "\033[0m"; constexpr const char* B = "\033[1m";
constexpr const char* DIM = "\033[2m"; constexpr const char* CYAN = "\033[36m";
constexpr const char* GRN = "\033[32m"; constexpr const char* YEL = "\033[33m";
constexpr const char* RED = "\033[31m"; constexpr const char* GRY = "\033[90m";
}

// Human-friendly big-number and duration formatting.
std::string human_count(double n) {
    char b[32];
    const char* u = "";
    if (n >= 1e12) { n /= 1e12; u = "T"; }
    else if (n >= 1e9) { n /= 1e9; u = "G"; }
    else if (n >= 1e6) { n /= 1e6; u = "M"; }
    else if (n >= 1e3) { n /= 1e3; u = "k"; }
    std::snprintf(b, sizeof b, u[0] ? "%.2f%s" : "%.0f%s", n, u);
    return b;
}

std::string human_time(double s) {
    if (s < 0 || !std::isfinite(s)) s = 0;
    int t = (int)(s + 0.5);
    char b[24];
    if (t >= 3600) std::snprintf(b, sizeof b, "%d:%02d:%02d", t / 3600, (t % 3600) / 60, t % 60);
    else std::snprintf(b, sizeof b, "%d:%02d", t / 60, t % 60);
    return b;
}


// Owns every word list so SlotPlan can hold stable pointers into them.
// std::deque, not std::vector: a later add() must not invalidate the pointers
// returned by earlier ones.
struct Corpus {
    std::deque<std::vector<std::string>> lists;
    const std::vector<std::string>* add(std::vector<std::string> v) {
        lists.push_back(std::move(v));
        return &lists.back();
    }
};

void usage(const char* prog) {
    std::fprintf(stderr,
        "nidhunt - recover PS5 symbol names from NID hashes\n\n"
        "usage: %s -t TARGETS (-v VOCAB -d DEPTH | -s SLOT [-s SLOT ...]) [options]\n\n"
        "targets:\n"
        "  -t, --targets FILE   NIDs to search for; one 11-char NID per line,\n"
        "                       optional annotation after whitespace (kept in output)\n\n"
        "candidate shape (pick one):\n"
        "  combinator:  -v, --vocab FILE   and   -d, --depth N\n"
        "                       names of 1..N words, each word drawn from VOCAB\n"
        "  grammar:     -s, --slot FILE    (repeatable, one per position)\n"
        "                       exactly one word per slot, in the order given\n\n"
        "shared options:\n"
        "  -p, --prefix STR     fixed leading text, e.g. sceVideoOut (default: none)\n"
        "  -S, --suffix FILE    suffix list; the empty suffix is always included too\n"
        "      --backend B      cpu | gpu | auto   (default auto)\n"
        "      --threads N      CPU worker threads (default: all cores)\n"
        "      --device N       OpenCL GPU index to use (see --list-devices; default 0)\n"
        "      --self-test      verify the hashing against a known NID and exit\n"
        "      --list-devices   list OpenCL GPUs and exit\n"
        "  -h, --help\n\n"
        "A candidate name is  prefix + slot0 + slot1 + ... (+ suffix)  and a hit is\n"
        "found when first8(SHA1(name + SALT)) equals a target NID. The search stops\n"
        "as soon as every target NID has been found. Hits print to stdout as:\n"
        "  HIT <nid> <name>   [annotation]\n"
        "Names longer than %d characters are skipped. Use --vocab/--depth OR --slot,\n"
        "not both. Set NO_COLOR to disable the progress bar's colors.\n", prog, (int)MAX_NAME);
}

bool parse_args(int argc, char** argv, Config& c) {
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto val = [&](const char* name) -> std::string {
            if (i + 1 >= argc) { std::fprintf(stderr, "%s needs an argument\n", name); std::exit(1); }
            return argv[++i];
        };
        if (a == "-t" || a == "--targets") c.targets_path = val("--targets");
        else if (a == "-v" || a == "--vocab") c.vocab_path = val("--vocab");
        else if (a == "-d" || a == "--depth") c.depth = std::atoi(val("--depth").c_str());
        else if (a == "-s" || a == "--slot") c.slot_paths.push_back(val("--slot"));
        else if (a == "-p" || a == "--prefix") c.prefix = val("--prefix");
        else if (a == "-S" || a == "--suffix") c.suffix_path = val("--suffix");
        else if (a == "--backend") c.backend = val("--backend");
        else if (a == "--threads") c.threads = std::atoi(val("--threads").c_str());
        else if (a == "--device") c.device = std::atoi(val("--device").c_str());
        else if (a == "--self-test") c.self_test = true;
        else if (a == "--list-devices") c.list_devices = true;
        else if (a == "-h" || a == "--help") c.help = true;
        else { std::fprintf(stderr, "unknown argument: %s\n", a.c_str()); return false; }
    }
    return true;
}

bool run_self_test() {
    // Canonical community reference: this name hashes to this NID.
    const std::string name = "sceNpSessionSignalingCreateContext";
    const std::string want = "GtuZGmN-tKw";
    bool ok = true;
    std::string got_scalar = nid_of_key(key_of_name(name, false));
    if (got_scalar != want) { std::fprintf(stderr, "self-test FAIL (scalar): %s != %s\n", got_scalar.c_str(), want.c_str()); ok = false; }
    if (shani_available()) {
        std::string got_ni = nid_of_key(key_of_name(name, true));
        if (got_ni != want) { std::fprintf(stderr, "self-test FAIL (sha-ni): %s != %s\n", got_ni.c_str(), want.c_str()); ok = false; }
    }
    // Round-trip the NID<->key codec.
    if (nid_of_key(key_of_nid(want)) != want) { std::fprintf(stderr, "self-test FAIL: codec round-trip\n"); ok = false; }
    if (ok) std::fprintf(stderr, "self-test OK (sha-ni=%s): %s -> %s\n", shani_available() ? "yes" : "no", name.c_str(), want.c_str());
    return ok;
}

// Read a word list and drop words that could never appear in a hit (longer
// than MAX_NAME), warning how many were dropped.
std::vector<std::string> load_words(const std::string& path, const char* what) {
    std::vector<std::string> v = read_lines(path);
    std::vector<std::string> keep;
    keep.reserve(v.size());
    size_t dropped = 0;
    for (auto& w : v) { if (w.size() > MAX_NAME) ++dropped; else keep.push_back(std::move(w)); }
    if (dropped)
        std::fprintf(stderr, "nidhunt: dropped %zu %s word(s) longer than %zu chars\n",
                     dropped, what, (size_t)MAX_NAME);
    return keep;
}

// Build the list of search plans from the config. Fatally rejects an over-long
// prefix and any empty slot so neither backend can hit an out-of-bounds or a
// divide-by-zero, and so CPU and GPU always behave identically.
std::vector<SlotPlan> build_plans(const Config& c, Corpus& corp) {
    if (c.prefix.size() > MAX_NAME) {
        std::fprintf(stderr, "nidhunt: --prefix is longer than the %zu-char limit\n", (size_t)MAX_NAME);
        std::exit(1);
    }
    std::vector<SlotPlan> plans;
    const std::vector<std::string>* suffix_slot = nullptr;
    if (!c.suffix_path.empty()) {
        std::vector<std::string> suf = load_words(c.suffix_path, "suffix");
        suf.insert(suf.begin(), "");  // "" = no suffix (always kept, so the slot is never empty)
        suffix_slot = corp.add(std::move(suf));
    }
    if (!c.vocab_path.empty()) {  // combinator: depth sweep
        std::vector<std::string> vv = load_words(c.vocab_path, "vocab");
        if (vv.empty()) { std::fprintf(stderr, "nidhunt: vocab '%s' has no usable words\n", c.vocab_path.c_str()); std::exit(1); }
        const std::vector<std::string>* vocab = corp.add(std::move(vv));
        for (int k = 1; k <= c.depth; ++k) {
            SlotPlan p;
            p.prefix = c.prefix;
            for (int j = 0; j < k; ++j) p.slots.push_back(vocab);
            if (suffix_slot) p.slots.push_back(suffix_slot);
            plans.push_back(std::move(p));
        }
    } else {  // grammar: one plan, one slot per --slot file
        SlotPlan p;
        p.prefix = c.prefix;
        for (auto& sp : c.slot_paths) {
            std::vector<std::string> sv = load_words(sp, "slot");
            if (sv.empty()) { std::fprintf(stderr, "nidhunt: slot '%s' has no usable words\n", sp.c_str()); std::exit(1); }
            p.slots.push_back(corp.add(std::move(sv)));
        }
        if (suffix_slot) p.slots.push_back(suffix_slot);
        plans.push_back(std::move(p));
    }
    return plans;
}

// Verify a candidate index against the targets on the CPU and print it.
// Tracks which distinct target keys have been found; once every target is
// found, all_found is set and the backends stop early.
struct Reporter {
    const std::vector<Target>& targets;
    std::unordered_map<uint64_t, std::string> note;
    std::unordered_set<uint64_t> found;
    std::mutex mu;  // also serializes stdout hits against the stderr progress bar
    size_t hits = 0;
    std::atomic<bool> all_found{false};
    const Ui* ui = nullptr;
    explicit Reporter(const std::vector<Target>& t) : targets(t) {
        for (auto& x : t) note[x.key] = x.note;
    }
    void report(const SlotPlan& plan, uint64_t idx, bool use_ni) {
        std::string name = plan.name_at(idx);
        uint64_t key = key_of_name(name, use_ni);
        auto it = note.find(key);
        std::lock_guard<std::mutex> lk(mu);
        if (ui && ui->err_tty) { std::fprintf(stderr, "\r\033[K"); std::fflush(stderr); }  // wipe the bar
        if (it == note.end()) {  // GPU produced an index the CPU disagrees with
            std::fprintf(stderr, "%swarning:%s GPU/CPU verification mismatch for %s (%s)\n",
                         ui ? ui->e(ansi::YEL).c_str() : "", ui ? ui->e(ansi::RST).c_str() : "",
                         nid_of_key(key).c_str(), name.c_str());
            std::fflush(stderr);
            return;
        }
        bool first = found.insert(key).second;
        if (first) ++hits;
        bool col = ui && ui->out_tty;
        std::printf("%sHIT%s %s %s%s%s%s%s\n",
                    col ? "\033[1;32m" : "", col ? "\033[0m" : "",
                    nid_of_key(key).c_str(),
                    col ? "\033[1m" : "", name.c_str(), col ? "\033[0m" : "",
                    it->second.empty() ? "" : "   ",
                    it->second.c_str());
        std::fflush(stdout);
        if (found.size() == note.size()) all_found.store(true, std::memory_order_relaxed);
    }
};

// Live progress bar on stderr: fraction, candidates done/total, rate, elapsed,
// ETA, hits, and the current plan. Runs on its own thread; shares Reporter::mu
// so a HIT line never interleaves with a bar redraw.
struct Progress {
    std::atomic<uint64_t>& done;
    uint64_t total;
    Reporter& rep;
    const Ui& ui;
    std::chrono::steady_clock::time_point t0;
    std::atomic<int> plan_idx{0};
    int nplans = 1;
    std::atomic<bool> stop{false};
    std::thread th;

    Progress(std::atomic<uint64_t>& d, uint64_t tot, Reporter& r, const Ui& u,
             std::chrono::steady_clock::time_point start, int np)
        : done(d), total(tot), rep(r), ui(u), t0(start), nplans(np) {}

    void start() { if (ui.err_tty) th = std::thread([this] { loop(); }); }
    void loop() {
        while (!stop.load(std::memory_order_relaxed)) {
            render();
            for (int i = 0; i < 12 && !stop.load(std::memory_order_relaxed); ++i)
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    void render() {
        uint64_t d = done.load(std::memory_order_relaxed);
        double el = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        double rate = el > 0 ? d / el : 0;
        double frac = total ? (double)d / (double)total : 0;
        if (frac > 1) frac = 1;
        double eta = (rate > 0 && total > d) ? (double)(total - d) / rate : 0;
        const int W = 22;
        int fill = (int)(frac * W + 0.5);
        if (fill > W) fill = W;
        std::string bar;
        for (int i = 0; i < fill; ++i) bar += "\xE2\x96\x88";       // full block
        for (int i = fill; i < W; ++i) bar += "\xE2\x96\x91";       // light shade
        std::string plan;
        if (nplans > 1) {
            char pb[32];
            std::snprintf(pb, sizeof pb, "   %splan %d/%d%s",
                          ui.e(ansi::GRY).c_str(), plan_idx.load() + 1, nplans, ui.e(ansi::RST).c_str());
            plan = pb;
        }
        std::string doneH = human_count((double)d), totalH = human_count((double)total);
        std::string rateH = human_count(rate), elH = human_time(el), etaH = human_time(eta);
        std::string b = ui.e(ansi::B), rst = ui.e(ansi::RST), cyan = ui.e(ansi::CYAN);
        std::string grn = ui.e(ansi::GRN), gry = ui.e(ansi::GRY);
        std::string hitcol = rep.hits ? grn : gry;
        char line[640];
        std::snprintf(line, sizeof line,
            "\r\033[K %s%3d%%%s %s%s%s  %s / %s  %s%s/s%s  %s%s eta %s%s  %shits %zu/%zu%s%s",
            b.c_str(), (int)(frac * 100), rst.c_str(),
            cyan.c_str(), bar.c_str(), rst.c_str(),
            doneH.c_str(), totalH.c_str(),
            grn.c_str(), rateH.c_str(), rst.c_str(),
            gry.c_str(), elH.c_str(), etaH.c_str(), rst.c_str(),
            hitcol.c_str(), rep.hits, rep.note.size(), rst.c_str(), plan.c_str());
        std::lock_guard<std::mutex> lk(rep.mu);
        std::fprintf(stderr, "%s", line);
        std::fflush(stderr);
    }
    void finish() {
        stop.store(true, std::memory_order_relaxed);
        if (th.joinable()) th.join();
        if (ui.err_tty) { std::fprintf(stderr, "\r\033[K"); std::fflush(stderr); }
    }
};

// --- CPU backend ------------------------------------------------------------

// Appends the salt in place and hashes. always_inline so it folds into the
// worker (which carries NIDHUNT_WORKER_ATTR): on MinGW the SHA-NI spills then
// run on the worker's force-aligned, non-vectorized frame, with no per-call
// overhead; elsewhere it is an ordinary inline.
static NIDHUNT_AINLINE uint64_t nidhunt_do_hash(uint8_t* buf, size_t len, bool use_ni) {
    std::memcpy(buf + len, SALT, 16);
#ifdef NIDHUNT_HAVE_SHANI
    return use_ni ? sha1_first8_inplace<true>(buf, len + 16)
                  : sha1_first8_inplace<false>(buf, len + 16);
#else
    (void)use_ni;
    return sha1_first8_inplace<false>(buf, len + 16);
#endif
}

// Per-thread work. The search space is split by "head index": every slot except
// the last ("fast") slot forms the head space. A thread pulls a head index,
// builds the name head once (prefix + head words), then sweeps the fast slot's
// words reusing that head. With one slot there is no fast slot and the head
// space is that slot. Parallelism equals the head-space size, so threads get
// work no matter which slot is largest.
struct CpuJob {
    const SlotPlan* plan;
    const std::vector<uint64_t>* keys;    // sorted target keys (binary-searched on a bloom hit)
    const std::vector<uint64_t>* weight;  // radix weight per slot
    uint64_t bloom;                       // OR of (1<<(key&63)); one-instruction reject
    size_t ns, fast, nouter;              // fast = ns-1 (SIZE_MAX if ns==1); nouter = head slot count
    uint64_t headspace;
    bool use_ni;
    Reporter* rep;
    std::atomic<uint64_t>* next;
    std::atomic<uint64_t>* done;
};

NIDHUNT_WORKER_ATTR
static void cpu_worker(CpuJob job) {
    const SlotPlan& plan = *job.plan;
    const std::vector<uint64_t>& keys = *job.keys;
    const uint64_t bloom = job.bloom;
    const std::vector<uint64_t>& weight = *job.weight;
    const size_t fast = job.fast, nouter = job.nouter;
    const uint64_t headspace = job.headspace;
    const bool use_ni = job.use_ni;
    alignas(16) uint8_t buf[256];  // name + salt + SHA-1 padding, hashed in place
    const size_t plen = plan.prefix.size();
    std::memcpy(buf, plan.prefix.data(), plen);  // prefix is validated <= MAX_NAME
    std::atomic<bool>& all_found = job.rep->all_found;

    const std::vector<std::string>* fastwords = (fast == (size_t)-1) ? nullptr : plan.slots[fast];
    const size_t fastn = fastwords ? fastwords->size() : 1;

    for (;;) {
        if (all_found.load(std::memory_order_relaxed)) break;  // every target found
        uint64_t h = job.next->fetch_add(1);
        if (h >= headspace) break;

        // Decode h into the head slots (slot 0 fastest) and build the head.
        size_t head = plen;
        uint64_t head_idx = 0;
        bool toolong = false;
        uint64_t rem = h;
        for (size_t j = 0; j < nouter; ++j) {
            const std::vector<std::string>& s = *plan.slots[j];
            size_t d = (size_t)(rem % s.size());
            rem /= s.size();
            head_idx += (uint64_t)d * weight[j];
            const std::string& wrd = s[d];
            if (head + wrd.size() > MAX_NAME) { toolong = true; break; }  // skip, never OOB
            std::memcpy(buf + head, wrd.data(), wrd.size());
            head += wrd.size();
        }

        uint64_t local = fastn;  // every head covers fastn candidates (counted even if skipped)
        if (!toolong) {
            if (!fastwords) {  // ns == 1
                uint64_t key = nidhunt_do_hash(buf, head, use_ni);
                if (((bloom >> (key & 63)) & 1) && std::binary_search(keys.begin(), keys.end(), key)) job.rep->report(plan, head_idx, use_ni);
            } else {
                for (size_t fd = 0; fd < fastn; ++fd) {
                    const std::string& fw = (*fastwords)[fd];
                    if (head + fw.size() > MAX_NAME) continue;  // skip, do not truncate (GPU parity)
                    std::memcpy(buf + head, fw.data(), fw.size());
                    uint64_t key = nidhunt_do_hash(buf, head + fw.size(), use_ni);
                    if (((bloom >> (key & 63)) & 1) && std::binary_search(keys.begin(), keys.end(), key)) job.rep->report(plan, head_idx + (uint64_t)fd * weight[fast], use_ni);
                    if ((fd & 0x3FF) == 0x3FF && all_found.load(std::memory_order_relaxed)) break;
                }
            }
        }
        *job.done += local;
    }
}

void hash_plan_cpu(const SlotPlan& plan, const std::vector<uint64_t>& keys, int threads,
                   bool use_ni, Reporter& rep, std::atomic<uint64_t>& done) {
    size_t ns = plan.slots.size();
    if (ns == 0) return;
    size_t fast = ns >= 2 ? ns - 1 : (size_t)-1;
    size_t nouter = (fast == (size_t)-1) ? 1 : fast;  // head slots = [0, nouter)

    // Radix weight of each slot: turns digit values into the global candidate
    // index that name_at() expects.
    std::vector<uint64_t> weight(ns);
    uint64_t w = 1;
    for (size_t j = 0; j < ns; ++j) { weight[j] = w; w *= (uint64_t)plan.slots[j]->size(); }

    uint64_t headspace = 1;
    for (size_t j = 0; j < nouter; ++j) headspace *= (uint64_t)plan.slots[j]->size();

    uint64_t bloom = 0;
    for (uint64_t k : keys) bloom |= (uint64_t)1 << (k & 63);

    std::atomic<uint64_t> next{0};
    CpuJob job{&plan, &keys, &weight, bloom, ns, fast, nouter, headspace, use_ni, &rep, &next, &done};
    std::vector<std::thread> pool;
    int n = threads < 1 ? 1 : threads;
    for (int i = 0; i < n; ++i) pool.emplace_back(cpu_worker, job);
    for (auto& t : pool) t.join();
}

// --- GPU backend ------------------------------------------------------------
#ifdef NIDHUNT_OPENCL

// Enumerate GPUs across platforms in a stable order. With list=true, print
// them with a global index. Returns the device at global index `want` (or the
// first if want < 0), nullptr if none / out of range.
cl_device_id pick_gpu(bool list, int want) {
    cl_platform_id plats[16]; cl_uint np = 0;
    clGetPlatformIDs(16, plats, &np);
    cl_device_id chosen = nullptr;
    int gi = 0;
    for (cl_uint i = 0; i < np; ++i) {
        cl_device_id devs[16]; cl_uint nd = 0;
        clGetDeviceIDs(plats[i], CL_DEVICE_TYPE_GPU, 16, devs, &nd);
        for (cl_uint j = 0; j < nd; ++j, ++gi) {
            if (list) {
                char name[256] = {0}; clGetDeviceInfo(devs[j], CL_DEVICE_NAME, sizeof name, name, nullptr);
                std::fprintf(stderr, "  [%d] %s\n", gi, name);
            }
            if (want < 0 ? (chosen == nullptr) : (gi == want)) chosen = devs[j];
        }
    }
    return chosen;
}

#define CK(x) do { cl_int e_ = (x); if (e_ != CL_SUCCESS) { std::fprintf(stderr, "OpenCL error %d at %s:%d\n", e_, __FILE__, __LINE__); std::exit(3); } } while (0)

// Device state plus a cache of kernels keyed by generated source, so plans that
// share a shape (same slot counts and prefix length) compile only once.
struct GpuCtx {
    cl_context ctx;
    cl_command_queue q;
    cl_device_id dev;
    std::unordered_map<std::string, cl_kernel> cache;
};

cl_kernel gpu_kernel_for(GpuCtx& g, const std::string& src) {
    auto it = g.cache.find(src);
    if (it != g.cache.end()) return it->second;
    cl_int err;
    const char* csrc = src.c_str();
    cl_program prog = clCreateProgramWithSource(g.ctx, 1, &csrc, nullptr, &err); CK(err);
    if (clBuildProgram(prog, 1, &g.dev, "-cl-std=CL1.2", nullptr, nullptr) != CL_SUCCESS) {
        char log[16384] = {0};
        clGetProgramBuildInfo(prog, g.dev, CL_PROGRAM_BUILD_LOG, sizeof log, log, nullptr);
        std::fprintf(stderr, "kernel build failed:\n%s\n", log);
        std::exit(3);
    }
    cl_kernel k = clCreateKernel(prog, "crack", &err); CK(err);
    g.cache[src] = k;
    return k;
}

void hash_plan_gpu(GpuCtx& g, const SlotPlan& plan, const std::vector<Target>& targets,
                   Reporter& rep, std::atomic<uint64_t>& done) {
    // Flatten every slot's words into one pool; each slot is [start, start+count).
    std::vector<uint8_t> wchars; std::vector<uint32_t> woff; std::vector<uint8_t> wlen;
    std::vector<std::pair<uint32_t, uint32_t>> slotsig;  // {count, start} per slot
    for (auto* s : plan.slots) {
        slotsig.push_back({(uint32_t)s->size(), (uint32_t)woff.size()});
        for (auto& word : *s) {
            woff.push_back((uint32_t)wchars.size());
            wlen.push_back((uint8_t)word.size());
            wchars.insert(wchars.end(), word.begin(), word.end());
        }
    }
    if (wchars.empty()) wchars.push_back(0);
    std::vector<uint64_t> tkeys; for (auto& t : targets) tkeys.push_back(t.key);
    std::vector<uint8_t> pf(plan.prefix.begin(), plan.prefix.end()); if (pf.empty()) pf.push_back(0);

    // Kernel specialized to this plan's slot counts and prefix length.
    cl_kernel kern = gpu_kernel_for(g, nidhunt_build_kernel(slotsig, (uint32_t)plan.prefix.size(), (uint32_t)MAX_NAME));

    cl_int err;
    auto mk = [&](const void* p, size_t n, cl_mem_flags f) {
        cl_mem m = clCreateBuffer(g.ctx, f | CL_MEM_COPY_HOST_PTR, n ? n : 1, const_cast<void*>(p), &err); CK(err); return m;
    };
    cl_mem bwc = mk(wchars.data(), wchars.size(), CL_MEM_READ_ONLY);
    cl_mem bwo = mk(woff.data(), woff.size() * 4, CL_MEM_READ_ONLY);
    cl_mem bwl = mk(wlen.data(), wlen.size(), CL_MEM_READ_ONLY);
    cl_mem bpf = mk(pf.data(), pf.size(), CL_MEM_READ_ONLY);
    cl_mem btg = mk(tkeys.data(), tkeys.size() * 8, CL_MEM_READ_ONLY);
    std::vector<uint64_t> hitbuf(1024, 0); uint32_t zero = 0;
    cl_mem bhits = mk(hitbuf.data(), hitbuf.size() * 8, CL_MEM_READ_WRITE);
    cl_mem bn = mk(&zero, 4, CL_MEM_READ_WRITE);

    uint32_t nt = (uint32_t)tkeys.size();
    uint64_t total = plan.count();
    // Args that do not change across batches.
    CK(clSetKernelArg(kern, 0, sizeof(cl_mem), &bwc));
    CK(clSetKernelArg(kern, 1, sizeof(cl_mem), &bwo));
    CK(clSetKernelArg(kern, 2, sizeof(cl_mem), &bwl));
    CK(clSetKernelArg(kern, 3, sizeof(cl_mem), &bpf));
    CK(clSetKernelArg(kern, 5, 8, &total));
    CK(clSetKernelArg(kern, 6, sizeof(cl_mem), &btg));
    CK(clSetKernelArg(kern, 7, 4, &nt));
    CK(clSetKernelArg(kern, 8, sizeof(cl_mem), &bhits));
    CK(clSetKernelArg(kern, 9, sizeof(cl_mem), &bn));

    // Keep several batches in flight to hide the read-back latency, but force a
    // sync every INFLIGHT batches so no single GPU-busy window gets long enough
    // to trip the Windows GPU watchdog (TDR). The hit counter accrues across
    // the plan and is drained at each sync point.
    uint32_t zero2 = 0;
    const size_t BATCH = (size_t)1 << 26;
    const int INFLIGHT = 8;
    int pending = 0;
    auto drain = [&]() {
        CK(clFinish(g.q));
        uint32_t nh = 0;
        CK(clEnqueueReadBuffer(g.q, bn, CL_TRUE, 0, 4, &nh, 0, nullptr, nullptr));
        if (nh) {
            if (nh > 1024)
                std::fprintf(stderr, "nidhunt: warning: %u matches this window, only the first 1024 reported\n", nh);
            uint32_t ncopy = nh < 1024 ? nh : 1024;
            CK(clEnqueueReadBuffer(g.q, bhits, CL_TRUE, 0, 8 * ncopy, hitbuf.data(), 0, nullptr, nullptr));
            for (uint32_t i = 0; i < ncopy; ++i) rep.report(plan, hitbuf[i], false);
            CK(clEnqueueWriteBuffer(g.q, bn, CL_TRUE, 0, 4, &zero2, 0, nullptr, nullptr));
        }
        pending = 0;
    };
    for (uint64_t base = 0; base < total; base += BATCH) {
        uint64_t n = total - base < BATCH ? total - base : BATCH;
        CK(clSetKernelArg(kern, 4, 8, &base));
        size_t gsz = (size_t)((n + 255) / 256 * 256);
        CK(clEnqueueNDRangeKernel(g.q, kern, 1, nullptr, &gsz, nullptr, 0, nullptr, nullptr));
        done += n;
        if (++pending >= INFLIGHT) {
            drain();
            if (rep.all_found.load(std::memory_order_relaxed)) return;  // every target found
        }
    }
    if (pending) drain();
    // Buffers are intentionally not released: some ICDs (notably NVIDIA on
    // Windows) fault during teardown, and the OS reclaims everything at exit.
    for (cl_mem m : {bwc, bwo, bwl, bpf, btg, bhits, bn}) (void)m;
}
#endif  // NIDHUNT_OPENCL

}  // namespace

int main(int argc, char** argv) {
    Config c;
    if (!parse_args(argc, argv, c)) { usage(argv[0]); return 1; }
    if (c.help) { usage(argv[0]); return 0; }
    if (c.self_test) return run_self_test() ? 0 : 2;

    // The hashing must be correct before any search runs.
    if (!run_self_test()) return 2;

    bool want_gpu = (c.backend == "gpu") || (c.backend == "auto");
#ifndef NIDHUNT_OPENCL
    if (c.list_devices) { std::fprintf(stderr, "built without OpenCL support\n"); return 1; }
    if (c.backend == "gpu") { std::fprintf(stderr, "built without OpenCL support; rebuild with -DNIDHUNT_OPENCL\n"); return 1; }
    want_gpu = false;
    (void)want_gpu;
#endif

    if (c.targets_path.empty() && !c.list_devices) { std::fprintf(stderr, "no --targets given\n\n"); usage(argv[0]); return 1; }
    if (!c.vocab_path.empty() && !c.slot_paths.empty()) { std::fprintf(stderr, "give either --vocab/--depth or --slot, not both\n"); return 1; }
    if (!c.vocab_path.empty() && c.depth <= 0) { std::fprintf(stderr, "--vocab needs --depth > 0\n"); return 1; }
    if (c.vocab_path.empty() && c.slot_paths.empty() && !c.list_devices) { std::fprintf(stderr, "give either --vocab/--depth or --slot\n"); return 1; }

    int threads = c.threads > 0 ? c.threads : (int)std::thread::hardware_concurrency();
    if (threads < 1) threads = 1;
    if (threads > 1024) { std::fprintf(stderr, "nidhunt: clamping --threads to 1024\n"); threads = 1024; }
    // NIDHUNT_NO_NI forces the portable scalar SHA-1 even where SHA-NI exists
    // (lets the scalar path be tested, and is a fallback if SHA-NI misbehaves).
    bool use_ni = shani_available() && std::getenv("NIDHUNT_NO_NI") == nullptr;
    Ui ui = Ui::detect();

#ifdef NIDHUNT_OPENCL
    GpuCtx gpu{};
    char dname[256] = "GPU";
    if (want_gpu || c.list_devices) {
        if (c.list_devices) std::fprintf(stderr, "OpenCL GPUs:\n");
        cl_device_id dev = pick_gpu(c.list_devices, c.list_devices ? -1 : c.device);
        if (c.list_devices) return dev ? 0 : 1;
        if (!dev) {
            if (c.backend == "gpu") {
                std::fprintf(stderr, c.device >= 0 ? "no OpenCL GPU at index %d (see --list-devices)\n"
                                                    : "no OpenCL GPU found\n", c.device);
                return 3;
            }
            want_gpu = false;  // auto: fall back to CPU
            std::fprintf(stderr, "nidhunt: no OpenCL GPU; using CPU\n");
        } else {
            clGetDeviceInfo(dev, CL_DEVICE_NAME, sizeof dname, dname, nullptr);
            cl_int err;
            gpu.dev = dev;
            gpu.ctx = clCreateContext(nullptr, 1, &dev, nullptr, nullptr, &err); CK(err);
            gpu.q = clCreateCommandQueue(gpu.ctx, dev, 0, &err); CK(err);
            // Kernels are compiled lazily per plan shape (see gpu_kernel_for).
        }
    }
#else
    if (c.list_devices) return 1;
#endif

    std::vector<Target> targets = read_targets(c.targets_path);
    if (targets.empty()) { std::fprintf(stderr, "nidhunt: no valid NIDs in %s\n", c.targets_path.c_str()); return 1; }
    Corpus corp;
    std::vector<SlotPlan> plans = build_plans(c, corp);

    // Total candidate count, with overflow detection (a space > 2^64 can't be
    // enumerated as a linear index).
    uint64_t grand = 0; bool overflow = false;
    for (auto& p : plans) {
        uint64_t cnt = p.count();
        if (cnt == UINT64_MAX || __builtin_add_overflow(grand, cnt, &grand)) overflow = true;
    }
    if (overflow) {
        std::fprintf(stderr, "nidhunt: search space exceeds 2^64; narrow it (smaller vocab or lower depth)\n");
        return 1;
    }

    std::unordered_set<uint64_t> target_keys;
    for (auto& t : targets) target_keys.insert(t.key);
    const size_t ntargets = target_keys.size();  // distinct NIDs
    std::vector<uint64_t> target_key_vec(target_keys.begin(), target_keys.end());
    std::sort(target_key_vec.begin(), target_key_vec.end());  // for the CPU binary search

    std::string label;
#ifdef NIDHUNT_OPENCL
    if (want_gpu) label = std::string("GPU ") + dname;
#endif
    if (label.empty())
        label = (use_ni ? "CPU SHA-NI x" : "CPU scalar x") + std::to_string(threads);

    // Banner (stderr).
    std::fprintf(stderr, "%s%snidhunt%s  %s%s%s\n",
                 ui.e(ansi::B).c_str(), ui.e(ansi::CYAN).c_str(), ui.e(ansi::RST).c_str(),
                 ui.e(ansi::DIM).c_str(), label.c_str(), ui.e(ansi::RST).c_str());
    std::fprintf(stderr, "%stargets%s %zu   %splans%s %zu   %sspace%s %s candidates\n\n",
                 ui.e(ansi::GRY).c_str(), ui.e(ansi::RST).c_str(), ntargets,
                 ui.e(ansi::GRY).c_str(), ui.e(ansi::RST).c_str(), plans.size(),
                 ui.e(ansi::GRY).c_str(), ui.e(ansi::RST).c_str(), human_count((double)grand).c_str());

    Reporter rep(targets);
    rep.ui = &ui;
    std::atomic<uint64_t> done{0};
    auto t0 = std::chrono::steady_clock::now();
    Progress prog(done, grand, rep, ui, t0, (int)plans.size());
    prog.start();
    for (size_t pi = 0; pi < plans.size(); ++pi) {
        if (rep.all_found.load(std::memory_order_relaxed)) break;  // all targets found
        prog.plan_idx.store((int)pi, std::memory_order_relaxed);
#ifdef NIDHUNT_OPENCL
        if (want_gpu) { hash_plan_gpu(gpu, plans[pi], targets, rep, done); continue; }
#endif
        hash_plan_cpu(plans[pi], target_key_vec, threads, use_ni, rep, done);
    }
    prog.finish();
    double dt = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();

    // Summary (stderr).
    double rate = dt > 0 ? done.load() / dt : 0;
    const char* found_col = rep.hits == ntargets ? ui.e(ansi::GRN).c_str() : ui.e(ansi::YEL).c_str();
    std::fprintf(stderr, "%sdone%s  %s hashed in %s \xC2\xB7 %s/s \xC2\xB7 %s%zu/%zu%s targets found\n",
                 ui.e(ansi::B).c_str(), ui.e(ansi::RST).c_str(),
                 human_count((double)done.load()).c_str(), human_time(dt).c_str(), human_count(rate).c_str(),
                 found_col, rep.hits, ntargets, ui.e(ansi::RST).c_str());
    if (rep.hits < ntargets) {
        std::string un;
        std::unordered_set<uint64_t> shown;
        for (auto& t : targets)
            if (!rep.found.count(t.key) && shown.insert(t.key).second) { un += un.empty() ? "" : " "; un += t.nid; }
        if (!un.empty())
            std::fprintf(stderr, "%sunfound%s %s\n", ui.e(ansi::GRY).c_str(), ui.e(ansi::RST).c_str(), un.c_str());
    }
    return 0;
}
