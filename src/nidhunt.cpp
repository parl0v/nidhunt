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
#include <cstdint>
#include <deque>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "common.h"

#ifdef NIDHUNT_OPENCL
#define CL_TARGET_OPENCL_VERSION 120
#include <CL/cl.h>
#include "cl_kernel.h"
#endif

using namespace nidhunt;

namespace {

constexpr size_t MAX_NAME = 100;  // candidate length cap (name without salt)

struct Config {
    std::string targets_path, vocab_path, suffix_path, prefix, backend = "auto";
    std::vector<std::string> slot_paths;
    int depth = 0;
    int threads = 0;
    bool self_test = false, list_devices = false, help = false;
};

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
        "      --self-test      verify the hashing against a known NID and exit\n"
        "      --list-devices   list OpenCL GPUs and exit\n"
        "  -h, --help\n\n"
        "A candidate name is  prefix + slot0 + slot1 + ... (+ suffix)  and a hit is\n"
        "found when first8(SHA1(name + SALT)) equals a target NID. Hits print as:\n"
        "  HIT <nid> <name>   [annotation]\n", prog);
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

// Build the list of search plans from the config.
std::vector<SlotPlan> build_plans(const Config& c, Corpus& corp) {
    std::vector<SlotPlan> plans;
    const std::vector<std::string>* suffix_slot = nullptr;
    if (!c.suffix_path.empty()) {
        std::vector<std::string> suf = read_lines(c.suffix_path);
        suf.insert(suf.begin(), "");  // "" = no suffix
        suffix_slot = corp.add(std::move(suf));
    }
    if (!c.vocab_path.empty()) {  // combinator: depth sweep
        const std::vector<std::string>* vocab = corp.add(read_lines(c.vocab_path));
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
        for (auto& sp : c.slot_paths) p.slots.push_back(corp.add(read_lines(sp)));
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
    std::mutex mu;
    size_t hits = 0;
    std::atomic<bool> all_found{false};
    explicit Reporter(const std::vector<Target>& t) : targets(t) {
        for (auto& x : t) note[x.key] = x.note;
    }
    void report(const SlotPlan& plan, uint64_t idx, bool use_ni) {
        std::string name = plan.name_at(idx);
        uint64_t key = key_of_name(name, use_ni);
        auto it = note.find(key);
        std::lock_guard<std::mutex> lk(mu);
        if (it == note.end()) {  // GPU produced an index that the CPU disagrees with
            std::printf("WARN %s %s  (verification mismatch)\n", nid_of_key(key).c_str(), name.c_str());
        } else {
            if (found.insert(key).second) ++hits;  // count each distinct target once
            std::printf("HIT %s %s%s%s\n", nid_of_key(key).c_str(), name.c_str(),
                        it->second.empty() ? "" : "   ", it->second.c_str());
            if (found.size() == note.size()) all_found.store(true, std::memory_order_relaxed);
        }
        std::fflush(stdout);
    }
};

// --- CPU backend ------------------------------------------------------------

// Everything a worker thread needs. Passed by pointer to the thread entry.
// The last slot (fast = ns-1, when ns >= 2) is varied in the innermost loop;
// the "head" of the name (prefix + all earlier slots) is built once and reused
// across every word of the fast slot, so only the tail + hash is redone.
struct CpuJob {
    const SlotPlan* plan;
    const std::vector<Target>* targets;
    const std::vector<uint64_t>* weight;  // radix weight per slot
    size_t ns, pivot, pivot_n, fast;      // fast = ns-1, or SIZE_MAX if ns == 1
    bool use_ni;
    Reporter* rep;
    std::atomic<size_t>* next;
    std::atomic<uint64_t>* done;
};

// MinGW starts std::thread workers on a stack that is not 16-byte aligned, so
// the aligned SSE that GCC emits at -O2+ (auto-vectorized buffer stores, plus
// register spills on the SHA-NI path) faults and crashes the worker. Two
// defenses, together, make it reliable without any special build flags:
//   * force_align_arg_pointer realigns this frame to 16 bytes on entry, so this
//     function and everything it calls run on an aligned stack;
//   * no-tree-vectorize drops the aligned vectorized stores entirely.
// The SHA-1 is hand-written intrinsics, so neither costs throughput. The main
// thread is ABI-aligned, so the GPU path needs none of this.
__attribute__((force_align_arg_pointer, optimize("no-tree-vectorize", "no-tree-slp-vectorize")))
static void cpu_worker(CpuJob job) {
    const SlotPlan& plan = *job.plan;
    const std::vector<Target>& targets = *job.targets;
    const std::vector<uint64_t>& weight = *job.weight;
    const size_t ns = job.ns, pivot = job.pivot, pivot_n = job.pivot_n, fast = job.fast;
    const bool use_ni = job.use_ni;
    const size_t nt = targets.size();
    alignas(16) uint8_t buf[256];  // name + salt + SHA-1 padding, hashed in place
    const size_t plen = plan.prefix.size();
    std::memcpy(buf, plan.prefix.data(), plen);  // prefix is constant for the plan
    std::atomic<bool>& all_found = job.rep->all_found;

    // always_inline: this must fold into cpu_worker so the SHA-NI code runs on
    // cpu_worker's force-aligned frame. A non-inlined lambda would carry none
    // of the worker's attributes and could fault on MinGW's misaligned stack.
    auto hash_match = [&](size_t len, uint64_t idx) __attribute__((always_inline)) {
        if (len > MAX_NAME) return;
        std::memcpy(buf + len, SALT, 16);
#ifdef NIDHUNT_HAVE_SHANI
        uint64_t key = use_ni ? sha1_first8_inplace<true>(buf, len + 16)
                              : sha1_first8_inplace<false>(buf, len + 16);
#else
        uint64_t key = sha1_first8_inplace<false>(buf, len + 16);
#endif
        for (size_t t = 0; t < nt; ++t)
            if (key == targets[t].key) { job.rep->report(plan, idx, use_ni); break; }
    };

    std::vector<size_t> dig(ns, 0);
    for (;;) {
        if (all_found.load(std::memory_order_relaxed)) break;  // every target found
        size_t pv = job.next->fetch_add(1);
        if (pv >= pivot_n) break;
        for (size_t j = 0; j < ns; ++j) dig[j] = 0;
        dig[pivot] = pv;
        uint64_t local = 0;

        if (fast == (size_t)-1) {  // ns == 1: nothing to reuse, just hash the word
            const std::string& word = (*plan.slots[pivot])[pv];
            std::memcpy(buf + plen, word.data(), word.size());
            hash_match(plen + word.size(), (uint64_t)pv * weight[pivot]);
            *job.done += 1;
            continue;
        }

        const std::vector<std::string>& fastwords = *plan.slots[fast];
        const size_t fastn = fastwords.size();
        for (;;) {
            // Build the head (prefix + every slot except the fast one) once, then
            // reuse it across all fast-slot words.
            size_t head = plen;
            uint64_t head_idx = 0;
            for (size_t j = 0; j < fast; ++j) {
                const std::string& word = (*plan.slots[j])[dig[j]];
                std::memcpy(buf + head, word.data(), word.size());
                head += word.size();
                head_idx += (uint64_t)dig[j] * weight[j];
            }
            if (head <= MAX_NAME) {
                for (size_t fd = 0; fd < fastn; ++fd) {
                    const std::string& fw = fastwords[fd];
                    std::memcpy(buf + head, fw.data(), fw.size());
                    hash_match(head + fw.size(), head_idx + (uint64_t)fd * weight[fast]);
                }
            }
            local += fastn;
            if (all_found.load(std::memory_order_relaxed)) break;
            // Odometer over every slot except the pivot and the fast slot.
            size_t pos = 0;
            while (pos < ns) {
                if (pos == pivot || pos == fast) { ++pos; continue; }
                if (++dig[pos] < plan.slots[pos]->size()) break;
                dig[pos] = 0; ++pos;
            }
            if (pos >= ns) break;
        }
        *job.done += local;
    }
}

void hash_plan_cpu(const SlotPlan& plan, const std::vector<Target>& targets, int threads,
                   bool use_ni, Reporter& rep, std::atomic<uint64_t>& done) {
    size_t ns = plan.slots.size();
    if (ns == 0) return;
    // Vary the last slot innermost (fast); parallelize over the largest of the
    // remaining slots for load balance. With one slot there is no head to reuse.
    size_t fast = ns >= 2 ? ns - 1 : (size_t)-1;
    size_t pivot = 0;
    size_t pivot_hi = (ns >= 2) ? ns - 1 : ns;  // candidates for pivot: [0, pivot_hi)
    for (size_t j = 1; j < pivot_hi; ++j)
        if (plan.slots[j]->size() > plan.slots[pivot]->size()) pivot = j;
    size_t pivot_n = plan.slots[pivot]->size();

    // Radix weight of each slot: turns a local digit vector into the global
    // candidate index that name_at() expects.
    std::vector<uint64_t> weight(ns);
    uint64_t w = 1;
    for (size_t j = 0; j < ns; ++j) { weight[j] = w; w *= (uint64_t)plan.slots[j]->size(); }

    std::atomic<size_t> next{0};
    CpuJob job{&plan, &targets, &weight, ns, pivot, pivot_n, fast, use_ni, &rep, &next, &done};
    std::vector<std::thread> pool;
    for (int i = 0; i < threads; ++i) pool.emplace_back(cpu_worker, job);
    for (auto& t : pool) t.join();
}

// --- GPU backend ------------------------------------------------------------
#ifdef NIDHUNT_OPENCL

cl_device_id pick_gpu(bool list) {
    cl_platform_id plats[16]; cl_uint np = 0;
    clGetPlatformIDs(16, plats, &np);
    cl_device_id chosen = nullptr;
    for (cl_uint i = 0; i < np; ++i) {
        cl_device_id devs[16]; cl_uint nd = 0;
        clGetDeviceIDs(plats[i], CL_DEVICE_TYPE_GPU, 16, devs, &nd);
        for (cl_uint j = 0; j < nd; ++j) {
            char name[256] = {0}; clGetDeviceInfo(devs[j], CL_DEVICE_NAME, sizeof name, name, nullptr);
            if (list) std::fprintf(stderr, "  platform %u device %u: %s\n", i, j, name);
            if (!chosen) chosen = devs[j];
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
    cl_kernel kern = gpu_kernel_for(g, nidhunt_build_kernel(slotsig, (uint32_t)plan.prefix.size()));

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
    clSetKernelArg(kern, 0, sizeof(cl_mem), &bwc);
    clSetKernelArg(kern, 1, sizeof(cl_mem), &bwo);
    clSetKernelArg(kern, 2, sizeof(cl_mem), &bwl);
    clSetKernelArg(kern, 3, sizeof(cl_mem), &bpf);
    clSetKernelArg(kern, 5, 8, &total);
    clSetKernelArg(kern, 6, sizeof(cl_mem), &btg);
    clSetKernelArg(kern, 7, 4, &nt);
    clSetKernelArg(kern, 8, sizeof(cl_mem), &bhits);
    clSetKernelArg(kern, 9, sizeof(cl_mem), &bn);

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
            uint32_t ncopy = nh < 1024 ? nh : 1024;
            CK(clEnqueueReadBuffer(g.q, bhits, CL_TRUE, 0, 8 * ncopy, hitbuf.data(), 0, nullptr, nullptr));
            for (uint32_t i = 0; i < ncopy; ++i) rep.report(plan, hitbuf[i], false);
            CK(clEnqueueWriteBuffer(g.q, bn, CL_TRUE, 0, 4, &zero2, 0, nullptr, nullptr));
        }
        pending = 0;
    };
    for (uint64_t base = 0; base < total; base += BATCH) {
        uint64_t n = total - base < BATCH ? total - base : BATCH;
        clSetKernelArg(kern, 4, 8, &base);
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
    if (!c.vocab_path.empty() && c.slot_paths.empty() && c.depth <= 0) { std::fprintf(stderr, "--vocab needs --depth > 0\n"); return 1; }
    if (c.vocab_path.empty() && c.slot_paths.empty() && !c.list_devices) { std::fprintf(stderr, "give either --vocab/--depth or --slot\n"); return 1; }

    int threads = c.threads > 0 ? c.threads : (int)std::thread::hardware_concurrency();
    if (threads < 1) threads = 1;
    bool use_ni = shani_available();

#ifdef NIDHUNT_OPENCL
    GpuCtx gpu{};
    char dname[256] = "GPU";
    if (want_gpu || c.list_devices) {
        if (c.list_devices) std::fprintf(stderr, "OpenCL GPUs:\n");
        cl_device_id dev = pick_gpu(c.list_devices);
        if (c.list_devices) return dev ? 0 : 1;
        if (!dev) {
            if (c.backend == "gpu") { std::fprintf(stderr, "no OpenCL GPU found\n"); return 3; }
            want_gpu = false;  // auto: fall back to CPU
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
    if (targets.empty()) { std::fprintf(stderr, "no valid NIDs in %s\n", c.targets_path.c_str()); return 1; }
    Corpus corp;
    std::vector<SlotPlan> plans = build_plans(c, corp);

    uint64_t grand = 0; for (auto& p : plans) grand += p.count();
    std::string label;
#ifdef NIDHUNT_OPENCL
    if (want_gpu) label = std::string("gpu (") + dname + ")";
#endif
    if (label.empty()) label = use_ni ? "cpu (sha-ni)" : "cpu (scalar)";
    std::fprintf(stderr, "backend=%s targets=%zu plans=%zu candidates=%.3e\n",
                 label.c_str(), targets.size(), plans.size(), (double)grand);

    Reporter rep(targets);
    std::atomic<uint64_t> done{0};
    auto t0 = std::chrono::steady_clock::now();
    for (auto& p : plans) {
        if (rep.all_found.load(std::memory_order_relaxed)) break;  // all targets found
#ifdef NIDHUNT_OPENCL
        if (want_gpu) { hash_plan_gpu(gpu, p, targets, rep, done); continue; }
#endif
        hash_plan_cpu(p, targets, threads, use_ni, rep, done);
    }
    double dt = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    std::fprintf(stderr, "done: %.3e hashes in %.1fs = %.1f M/s, %zu hit(s)\n",
                 (double)done.load(), dt, done.load() / (dt > 0 ? dt : 1e-9) / 1e6, rep.hits);
    return 0;
}
