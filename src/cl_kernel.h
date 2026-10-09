// SPDX-License-Identifier: GPL-3.0-or-later
// OpenCL kernel generator for the GPU backend. One work item per candidate.
//
// The kernel is generated per plan shape with the slot counts and starts baked
// in as literals, then compiled. Two wins fall out of that:
//   * the slot loop is fully unrolled (no per-slot indirection or branches);
//   * the mixed-radix `idx % count` / `idx /= count` become division by a
//     compile-time constant, which the OpenCL compiler turns into a magic
//     multiply-shift instead of a real (slow) integer division.
//
// The candidate model matches common.h exactly: a flat word pool (wchars/woff/
// wlen) is sliced into slots by [start, start+count). A candidate index decodes
// mixed-radix (slot 0 fastest-varying) to one word per slot; the name is
// prefix + words, SALT is appended and SHA1'd, and the first 8 digest bytes
// (big-endian) are compared with the target keys. Candidates whose name would
// exceed MAX_NAME are skipped (not truncated) exactly as on the CPU, so the two
// backends enumerate the identical space; every GPU hit is re-hashed on the host.
#ifndef NIDHUNT_CL_KERNEL_H
#define NIDHUNT_CL_KERNEL_H

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "common.h"

// SHA-1 block transform and the fixed head of the kernel.
static const char* NIDHUNT_KERNEL_PRELUDE = R"CLC(
__constant uchar SALT[16] = {0x51,0x8D,0x64,0xA6,0x35,0xDE,0xD8,0xC1,0xE6,0xB0,0x39,0xB1,0xC3,0xE5,0x52,0x30};

void sha1_block(uint* h, const uint* m) {
    uint w[80];
    for (int i = 0; i < 16; ++i) w[i] = m[i];
    for (int i = 16; i < 80; ++i) w[i] = rotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1u);
    uint a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    #pragma unroll
    for (int i = 0; i < 20; ++i) { uint t = rotate(a, 5u) + bitselect(d, c, b) + e + 0x5A827999u + w[i]; e = d; d = c; c = rotate(b, 30u); b = a; a = t; }
    #pragma unroll
    for (int i = 20; i < 40; ++i) { uint t = rotate(a, 5u) + (b ^ c ^ d) + e + 0x6ED9EBA1u + w[i]; e = d; d = c; c = rotate(b, 30u); b = a; a = t; }
    #pragma unroll
    for (int i = 40; i < 60; ++i) { uint t = rotate(a, 5u) + bitselect(c, b, c ^ d) + e + 0x8F1BBCDCu + w[i]; e = d; d = c; c = rotate(b, 30u); b = a; a = t; }
    #pragma unroll
    for (int i = 60; i < 80; ++i) { uint t = rotate(a, 5u) + (b ^ c ^ d) + e + 0xCA62C1D6u + w[i]; e = d; d = c; c = rotate(b, 30u); b = a; a = t; }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}
)CLC";

// Build a crack kernel specialized to one plan: slots is {count, start} per
// slot (slot 0 fastest-varying), plen is the prefix length. maxname is the
// candidate length cap (common.h MAX_NAME); the private buffer is sized for
// maxname + 16 salt + SHA-1 padding (<= 128 for maxname <= 103).
inline std::string nidhunt_build_kernel(const std::vector<std::pair<uint32_t, uint32_t>>& slots,
                                        uint32_t plen, uint32_t maxname) {
    char line[256];
    std::string s = NIDHUNT_KERNEL_PRELUDE;
    s += "__kernel void crack(__global const uchar* wchars, __global const uint* woff, __global const uchar* wlen,\n"
         "                    __constant uchar* prefix, ulong base, ulong total,\n"
         "                    __constant ulong* targets, uint ntargets, __global ulong* hits, __global uint* nhits) {\n"
         "    ulong gid = base + get_global_id(0);\n"
         "    if (gid >= total) return;\n"
         "    uchar buf[128];\n"
         "    uint len = 0, toolong = 0;\n";
    std::snprintf(line, sizeof line, "    const uint MAXNAME = %uu;\n", maxname);
    s += line;
    for (uint32_t i = 0; i < plen; ++i) {  // prefix bytes (unrolled), bounded
        std::snprintf(line, sizeof line,
            "    if (len < MAXNAME) buf[len++] = prefix[%u]; else toolong = 1;\n", i);
        s += line;
    }
    s += "    ulong idx = gid;\n    uint wi, o, l;\n";
    for (size_t j = 0; j < slots.size(); ++j) {
        uint32_t count = slots[j].first, start = slots[j].second;
        if (j + 1 < slots.size()) {
            std::snprintf(line, sizeof line, "    wi = %uu + (uint)(idx %% %uu); idx /= %uu;\n", start, count, count);
        } else {  // last slot: idx is already < count, so it is the digit
            std::snprintf(line, sizeof line, "    wi = %uu + (uint)idx;\n", start);
        }
        s += line;
        // Copy the word, but never past MAXNAME; mark toolong if it does not fit
        // (so the candidate is skipped, matching the CPU — not truncated).
        s += "    o = woff[wi]; l = wlen[wi];\n"
             "    for (uint i = 0; i < l; ++i) { if (len < MAXNAME) buf[len++] = wchars[o + i]; else toolong = 1; }\n";
    }
    s += "    if (!toolong) {\n"
         "        for (int i = 0; i < 16; ++i) buf[len + i] = SALT[i];\n"
         "        uint L = len + 16;\n"
         "        uint nb = (L + 9 <= 64) ? 1 : 2;\n"
         "        uint end = nb * 64;\n"
         "        buf[L] = 0x80;\n"
         "        for (uint i = L + 1; i < end - 8; ++i) buf[i] = 0;\n"
         "        ulong bits = (ulong)L * 8;\n"
         "        for (int i = 0; i < 8; ++i) buf[end - 1 - i] = (uchar)(bits >> (8 * i));\n"
         "        uint h[5] = {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u};\n"
         "        uint m[16];\n"
         "        for (uint blk = 0; blk < nb; ++blk) {\n"
         "            for (int i = 0; i < 16; ++i) {\n"
         "                uint p = blk * 64 + i * 4;\n"
         "                m[i] = ((uint)buf[p] << 24) | ((uint)buf[p + 1] << 16) | ((uint)buf[p + 2] << 8) | buf[p + 3];\n"
         "            }\n"
         "            sha1_block(h, m);\n"
         "        }\n"
         "        ulong key = ((ulong)h[0] << 32) | h[1];\n"
         "        for (uint t = 0; t < ntargets; ++t) {\n"
         "            if (key == targets[t]) {\n"
         "                uint slot = atomic_inc(nhits);\n"
         "                if (slot < 1024) hits[slot] = gid;\n"
         "            }\n"
         "        }\n"
         "    }\n"
         "}\n";
    return s;
}

#endif
