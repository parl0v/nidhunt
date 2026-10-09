// OpenCL kernel for the GPU backend. One work item per candidate index.
//
// The candidate model matches common.h exactly: a flat word pool (wchars/woff/
// wlen) is sliced into slots by slotStart/slotCount. A candidate index decodes
// mixed-radix (slot 0 fastest-varying) to one word per slot; the name is
// prefix + words, then SALT is appended and SHA1'd. The first 8 digest bytes,
// taken big-endian, are compared against the target keys. Because the decode
// is identical to the CPU path, every GPU hit is re-hashed and checked on the
// host before it is printed.
#ifndef NIDHUNT_CL_KERNEL_H
#define NIDHUNT_CL_KERNEL_H

static const char* NIDHUNT_KERNEL = R"CLC(
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

// slotStart/slotCount live in __constant memory: they are read on every slot
// of every work item, and constant memory is broadcast-cached, far cheaper than
// the per-item __global reads this used to do (the main GPU regression). The
// bulk word pool stays __global.
__kernel void crack(__global const uchar* wchars, __global const uint* woff, __global const uchar* wlen,
                    __constant uint* slotStart, __constant uint* slotCount, uint nslots,
                    __constant uchar* prefix, uint plen, ulong base, ulong total,
                    __constant ulong* targets, uint ntargets, __global ulong* hits, __global uint* nhits) {
    ulong gid = base + get_global_id(0);
    if (gid >= total) return;
    uchar buf[128];
    uint len = 0;
    for (uint i = 0; i < plen && len < 100; ++i) buf[len++] = prefix[i];
    ulong idx = gid;
    for (uint j = 0; j < nslots; ++j) {
        // Last slot needs no divide: idx < slotCount[last] is guaranteed, so
        // the digit is just idx. Non-power-of-2 division is costly on GPU.
        uint d = (j + 1 == nslots) ? (uint)idx : (uint)(idx % slotCount[j]);
        if (j + 1 != nslots) idx /= slotCount[j];
        uint wi = slotStart[j] + d;
        uint o = woff[wi], l = wlen[wi];
        for (uint i = 0; i < l && len < 100; ++i) buf[len++] = wchars[o + i];
    }
    for (int i = 0; i < 16; ++i) buf[len + i] = SALT[i];
    uint L = len + 16;
    uint nb = (L + 9 <= 64) ? 1 : 2;
    uint end = nb * 64;
    buf[L] = 0x80;
    for (uint i = L + 1; i < end - 8; ++i) buf[i] = 0;  // zero only the padding gap
    ulong bits = (ulong)L * 8;
    for (int i = 0; i < 8; ++i) buf[end - 1 - i] = (uchar)(bits >> (8 * i));
    uint h[5] = {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u};
    uint m[16];
    for (uint blk = 0; blk < nb; ++blk) {
        for (int i = 0; i < 16; ++i) {
            uint p = blk * 64 + i * 4;
            m[i] = ((uint)buf[p] << 24) | ((uint)buf[p + 1] << 16) | ((uint)buf[p + 2] << 8) | buf[p + 3];
        }
        sha1_block(h, m);
    }
    ulong key = ((ulong)h[0] << 32) | h[1];
    for (uint t = 0; t < ntargets; ++t) {
        if (key == targets[t]) {
            uint slot = atomic_inc(nhits);
            if (slot < 1024) hits[slot] = gid;
        }
    }
}
)CLC";

#endif
