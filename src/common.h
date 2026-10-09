// Shared definitions for nidhunt: the PS5 NID codec, input parsing, and the
// slot-plan candidate model that both the CPU and GPU backends enumerate.
//
// A PS5 library exports each symbol under an 11-character NID. The NID is the
// first 8 bytes of SHA1(symbol_name + SALT), read big-endian and base64-encoded
// with the charset below (A-Za-z0-9+-, '-' in place of '/'). SALT is a fixed,
// public 16-byte value shipped in the system libraries; it is not a secret and
// not a key. nidhunt only ever hashes candidate *function names*.
#ifndef NIDHUNT_COMMON_H
#define NIDHUNT_COMMON_H

#include <cstdint>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include "sha1.h"

namespace nidhunt {

// Public NID salt from the PS5 system libraries (well known in the community).
static const uint8_t SALT[16] = {0x51, 0x8D, 0x64, 0xA6, 0x35, 0xDE, 0xD8, 0xC1,
                                 0xE6, 0xB0, 0x39, 0xB1, 0xC3, 0xE5, 0x52, 0x30};
static const char* CS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-";

// --- NID <-> 64-bit key -----------------------------------------------------
// A "key" is the first 8 digest bytes as a big-endian uint64_t: the same value
// sha1_first8() returns, so a hit is a plain integer compare.

inline uint64_t key_of_nid(const std::string& n) {
    uint64_t v = 0;
    for (int i = 0; i < 10; ++i) v |= (uint64_t)(std::strchr(CS, n[i]) - CS) << (58 - 6 * i);
    v |= (uint64_t)(std::strchr(CS, n[10]) - CS) >> 2;
    uint64_t be = 0;
    for (int i = 0; i < 8; ++i) be = be << 8 | ((v >> (8 * i)) & 0xFF);
    return be;
}

inline std::string nid_of_key(uint64_t be) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = v << 8 | ((be >> (8 * i)) & 0xFF);
    std::string s;
    for (int i = 0; i < 10; ++i) s += CS[(v >> (58 - 6 * i)) & 63];
    s += CS[(v & 15) << 2];
    return s;
}

// Hash a symbol name to its key (salt appended). Used for verification/self-test.
inline uint64_t key_of_name(const std::string& name, bool use_ni = false) {
    std::string m = name;
    m.append((const char*)SALT, 16);
    return sha1_first8((const uint8_t*)m.data(), m.size(), use_ni);
}

inline std::string nid_of_name(const std::string& name) { return nid_of_key(key_of_name(name)); }

// --- Input files ------------------------------------------------------------
// One token per line; blank lines and '#' comments ignored; CR and trailing
// spaces trimmed. "-" means "no file" (returns an empty list).

inline std::vector<std::string> read_lines(const std::string& path) {
    std::vector<std::string> out;
    if (path == "-" || path.empty()) return out;
    std::ifstream f(path);
    std::string l;
    while (std::getline(f, l)) {
        while (!l.empty() && (l.back() == '\r' || l.back() == ' ' || l.back() == '\t')) l.pop_back();
        if (l.empty() || l[0] == '#') continue;
        out.push_back(l);
    }
    return out;
}

// A targets file lists one NID per line; extra columns (name, library, notes)
// are kept so matched lines can be reported with their annotation. The NID is
// the first whitespace-separated token and must be 11 chars.
struct Target {
    uint64_t key;
    std::string nid;
    std::string note;  // remainder of the line after the NID, if any
};

inline std::vector<Target> read_targets(const std::string& path) {
    std::vector<Target> out;
    for (auto& line : read_lines(path)) {
        size_t sp = line.find_first_of(" \t");
        std::string nid = sp == std::string::npos ? line : line.substr(0, sp);
        if (nid.size() < 11) continue;
        nid = nid.substr(0, 11);
        std::string note = sp == std::string::npos ? "" : line.substr(line.find_first_not_of(" \t", sp));
        out.push_back({key_of_nid(nid), nid, note});
    }
    return out;
}

// --- Candidate model --------------------------------------------------------
// A candidate name is prefix + slot[0] + slot[1] + ... + slot[n-1], where each
// slot draws one word from its own list. The whole search is a list of such
// plans. The depth-sweep combinator expands to one plan per length; a grammar
// (per-position word lists) is a single plan. A suffix list is just another
// slot whose words include "" (the no-suffix case).
//
// Candidate index -> word digits is mixed-radix with slot[0] fastest-varying,
// identical on CPU and GPU so a GPU hit can be reproduced and verified on CPU.
struct SlotPlan {
    std::string prefix;
    std::vector<const std::vector<std::string>*> slots;

    uint64_t count() const {
        uint64_t c = 1;
        for (auto* s : slots) c *= (uint64_t)s->size();
        return c;
    }

    std::string name_at(uint64_t idx) const {
        std::string n = prefix;
        for (auto* s : slots) {
            uint32_t d = (uint32_t)(idx % s->size());
            idx /= s->size();
            n += (*s)[d];
        }
        return n;
    }
};

}  // namespace nidhunt
#endif
