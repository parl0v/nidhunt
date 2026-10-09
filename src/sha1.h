// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Josip Parlov (parl0v)
// Additional term (GPL-3.0 section 7b): conveyed or modified versions must preserve the author attribution "nidhunt by Josip Parlov (parl0v)" in their Appropriate Legal Notices (this CLI shows it in --version).
// SHA-1 compression used by nidhunt.
//
// Two implementations of the 64-byte block transform:
//   * sha1_block_scalar  - portable C++, works on any target.
//   * sha1_block_ni      - x86 SHA-NI intrinsics, ~5x faster, built only on x86.
//
// sha1_first8() hashes a whole message and returns the first 8 digest bytes as
// a big-endian uint64_t (the value a PS5 NID encodes). It picks the SHA-NI path
// at run time when the CPU advertises the extension, otherwise the scalar path.
#ifndef NIDHUNT_SHA1_H
#define NIDHUNT_SHA1_H

#include <cstdint>
#include <cstring>

// The x86 intrinsic header must be included at global scope, before any
// namespace: pulling it in inside a namespace would declare __m128i etc. there
// and break its include guards for later system headers (e.g. OpenCL's).
//
// Gated to x86 AND GCC/Clang: the SHA-NI path below uses GNU attributes
// (target(), force_align) and __builtin_cpu_supports, which MSVC does not
// provide. On MSVC (or any other compiler) nidhunt uses the portable scalar
// SHA-1 instead.
#if (defined(__x86_64__) || defined(__i386__)) && (defined(__GNUC__) || defined(__clang__))
#define NIDHUNT_HAVE_SHANI 1
#include <immintrin.h>
#endif

namespace nidhunt {

inline uint32_t rol(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

inline void sha1_block_scalar(uint32_t h[5], const uint8_t* p) {
    uint32_t w[80];
    for (int i = 0; i < 16; ++i)
        w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 | (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
    for (int i = 16; i < 80; ++i) w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    for (int i = 0; i < 80; ++i) {
        uint32_t f, k;
        if (i < 20)      { f = (b & c) | (~b & d);            k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d;                     k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d);   k = 0x8F1BBCDC; }
        else             { f = b ^ c ^ d;                     k = 0xCA62C1D6; }
        uint32_t t = rol(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rol(b, 30); b = a; a = t;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

#ifdef NIDHUNT_HAVE_SHANI
// On MinGW, std::thread worker stacks are not reliably 16-byte aligned, which
// faults the aligned SSE this code uses at -O2+. nidhunt handles that by
// realigning the worker frame itself (force_align_arg_pointer on cpu_worker in
// nidhunt.cpp), so this header needs no special handling.
__attribute__((target("sha,sse4.1,ssse3")))
inline void sha1_block_ni(uint32_t state[5], const uint8_t* data) {
    __m128i ABCD, ABCD_SAVE, E0, E0_SAVE, E1, M[4];
    const __m128i MASK = _mm_set_epi64x(0x0001020304050607ULL, 0x08090a0b0c0d0e0fULL);
    ABCD = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i*)state), 0x1B);
    E0 = _mm_set_epi32((int)state[4], 0, 0, 0);
    ABCD_SAVE = ABCD; E0_SAVE = E0;
    M[0] = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(data + 0)), MASK);
    E0 = _mm_add_epi32(E0, M[0]); E1 = ABCD; ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0);
    M[1] = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(data + 16)), MASK);
    E1 = _mm_sha1nexte_epu32(E1, M[1]); E0 = ABCD; ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 0); M[0] = _mm_sha1msg1_epu32(M[0], M[1]);
    M[2] = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(data + 32)), MASK);
    E0 = _mm_sha1nexte_epu32(E0, M[2]); E1 = ABCD; ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0); M[1] = _mm_sha1msg1_epu32(M[1], M[2]); M[0] = _mm_xor_si128(M[0], M[2]);
    M[3] = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(data + 48)), MASK);
    E1 = _mm_sha1nexte_epu32(E1, M[3]); E0 = ABCD; M[0] = _mm_sha1msg2_epu32(M[0], M[3]); ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 0); M[2] = _mm_sha1msg1_epu32(M[2], M[3]); M[1] = _mm_xor_si128(M[1], M[3]);
    E0 = _mm_sha1nexte_epu32(E0, M[0]); E1 = ABCD; M[1] = _mm_sha1msg2_epu32(M[1], M[0]); ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 0); M[3] = _mm_sha1msg1_epu32(M[3], M[0]); M[2] = _mm_xor_si128(M[2], M[0]);
    E1 = _mm_sha1nexte_epu32(E1, M[1]); E0 = ABCD; M[2] = _mm_sha1msg2_epu32(M[2], M[1]); ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1); M[0] = _mm_sha1msg1_epu32(M[0], M[1]); M[3] = _mm_xor_si128(M[3], M[1]);
    E0 = _mm_sha1nexte_epu32(E0, M[2]); E1 = ABCD; M[3] = _mm_sha1msg2_epu32(M[3], M[2]); ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 1); M[1] = _mm_sha1msg1_epu32(M[1], M[2]); M[0] = _mm_xor_si128(M[0], M[2]);
    E1 = _mm_sha1nexte_epu32(E1, M[3]); E0 = ABCD; M[0] = _mm_sha1msg2_epu32(M[0], M[3]); ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1); M[2] = _mm_sha1msg1_epu32(M[2], M[3]); M[1] = _mm_xor_si128(M[1], M[3]);
    E0 = _mm_sha1nexte_epu32(E0, M[0]); E1 = ABCD; M[1] = _mm_sha1msg2_epu32(M[1], M[0]); ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 1); M[3] = _mm_sha1msg1_epu32(M[3], M[0]); M[2] = _mm_xor_si128(M[2], M[0]);
    E1 = _mm_sha1nexte_epu32(E1, M[1]); E0 = ABCD; M[2] = _mm_sha1msg2_epu32(M[2], M[1]); ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 1); M[0] = _mm_sha1msg1_epu32(M[0], M[1]); M[3] = _mm_xor_si128(M[3], M[1]);
    E0 = _mm_sha1nexte_epu32(E0, M[2]); E1 = ABCD; M[3] = _mm_sha1msg2_epu32(M[3], M[2]); ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2); M[1] = _mm_sha1msg1_epu32(M[1], M[2]); M[0] = _mm_xor_si128(M[0], M[2]);
    E1 = _mm_sha1nexte_epu32(E1, M[3]); E0 = ABCD; M[0] = _mm_sha1msg2_epu32(M[0], M[3]); ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 2); M[2] = _mm_sha1msg1_epu32(M[2], M[3]); M[1] = _mm_xor_si128(M[1], M[3]);
    E0 = _mm_sha1nexte_epu32(E0, M[0]); E1 = ABCD; M[1] = _mm_sha1msg2_epu32(M[1], M[0]); ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2); M[3] = _mm_sha1msg1_epu32(M[3], M[0]); M[2] = _mm_xor_si128(M[2], M[0]);
    E1 = _mm_sha1nexte_epu32(E1, M[1]); E0 = ABCD; M[2] = _mm_sha1msg2_epu32(M[2], M[1]); ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 2); M[0] = _mm_sha1msg1_epu32(M[0], M[1]); M[3] = _mm_xor_si128(M[3], M[1]);
    E0 = _mm_sha1nexte_epu32(E0, M[2]); E1 = ABCD; M[3] = _mm_sha1msg2_epu32(M[3], M[2]); ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 2); M[1] = _mm_sha1msg1_epu32(M[1], M[2]); M[0] = _mm_xor_si128(M[0], M[2]);
    E1 = _mm_sha1nexte_epu32(E1, M[3]); E0 = ABCD; M[0] = _mm_sha1msg2_epu32(M[0], M[3]); ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3); M[2] = _mm_sha1msg1_epu32(M[2], M[3]); M[1] = _mm_xor_si128(M[1], M[3]);
    E0 = _mm_sha1nexte_epu32(E0, M[0]); E1 = ABCD; M[1] = _mm_sha1msg2_epu32(M[1], M[0]); ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 3); M[3] = _mm_sha1msg1_epu32(M[3], M[0]); M[2] = _mm_xor_si128(M[2], M[0]);
    E1 = _mm_sha1nexte_epu32(E1, M[1]); E0 = ABCD; M[2] = _mm_sha1msg2_epu32(M[2], M[1]); ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3); M[3] = _mm_xor_si128(M[3], M[1]);
    E0 = _mm_sha1nexte_epu32(E0, M[2]); E1 = ABCD; M[3] = _mm_sha1msg2_epu32(M[3], M[2]); ABCD = _mm_sha1rnds4_epu32(ABCD, E0, 3);
    E1 = _mm_sha1nexte_epu32(E1, M[3]); E0 = ABCD; ABCD = _mm_sha1rnds4_epu32(ABCD, E1, 3);
    E0 = _mm_sha1nexte_epu32(E0, E0_SAVE);
    ABCD = _mm_add_epi32(ABCD, ABCD_SAVE);
    _mm_storeu_si128((__m128i*)state, _mm_shuffle_epi32(ABCD, 0x1B));
    state[4] = (uint32_t)_mm_extract_epi32(E0, 3);
}
#endif  // x86

inline bool shani_available() {
#ifdef NIDHUNT_HAVE_SHANI
    return __builtin_cpu_supports("sha") != 0;
#else
    return false;
#endif
}

// Hash msg[0..len) and return the first 8 digest bytes as a big-endian uint64_t.
// buf must have room for len rounded up to the next 64-byte block (<= len + 72).
template <bool UseNI>
inline uint64_t sha1_first8_into(uint8_t* buf, const uint8_t* msg, size_t len) {
    uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    size_t full = len / 64 * 64;
    for (size_t off = 0; off < full; off += 64) {
#ifdef NIDHUNT_HAVE_SHANI
        if (UseNI) sha1_block_ni(h, msg + off); else sha1_block_scalar(h, msg + off);
#else
        sha1_block_scalar(h, msg + off);
#endif
    }
    size_t rem = len - full;
    std::memcpy(buf, msg + full, rem);
    buf[rem] = 0x80;
    size_t padlen = (rem + 1 + 8 <= 64) ? 64 : 128;
    std::memset(buf + rem + 1, 0, padlen - rem - 1);
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; ++i) buf[padlen - 1 - i] = (uint8_t)(bits >> (8 * i));
#ifdef NIDHUNT_HAVE_SHANI
    if (UseNI) { sha1_block_ni(h, buf); if (padlen == 128) sha1_block_ni(h, buf + 64); }
    else       { sha1_block_scalar(h, buf); if (padlen == 128) sha1_block_scalar(h, buf + 64); }
#else
    sha1_block_scalar(h, buf); if (padlen == 128) sha1_block_scalar(h, buf + 64);
#endif
    return (uint64_t)h[0] << 32 | h[1];
}

// Hash msg[0..len) in place and return the first 8 digest bytes big-endian.
// The caller's buffer must have room for the SHA-1 padding: at least
// round_up(len + 9, 64) bytes (<= len + 72). Avoids the message copy that
// sha1_first8_into does, so it is the hot-path entry for the CPU backend.
template <bool UseNI>
inline uint64_t sha1_first8_inplace(uint8_t* buf, size_t len) {
    uint32_t h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    size_t padlen = ((len + 9 + 63) / 64) * 64;
    buf[len] = 0x80;
    std::memset(buf + len + 1, 0, padlen - len - 9);
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; ++i) buf[padlen - 1 - i] = (uint8_t)(bits >> (8 * i));
    for (size_t off = 0; off < padlen; off += 64) {
#ifdef NIDHUNT_HAVE_SHANI
        if (UseNI) sha1_block_ni(h, buf + off); else sha1_block_scalar(h, buf + off);
#else
        sha1_block_scalar(h, buf + off);
#endif
    }
    return (uint64_t)h[0] << 32 | h[1];
}

// Convenience wrapper with an internal scratch buffer (used off the hot path).
inline uint64_t sha1_first8(const uint8_t* msg, size_t len, bool use_ni) {
    uint8_t buf[256];
#ifdef NIDHUNT_HAVE_SHANI
    if (use_ni) return sha1_first8_into<true>(buf, msg, len);
#endif
    (void)use_ni;
    return sha1_first8_into<false>(buf, msg, len);
}

}  // namespace nidhunt
#endif
