#!/usr/bin/env bash
# Build nidhunt. Produces ./nidhunt (CPU) and, when OpenCL is available,
# ./nidhunt-gpu (CPU + GPU backends).
#
#   ./build.sh            # autodetect OpenCL
#   ./build.sh cpu        # CPU binary only
#   ./build.sh gpu        # require OpenCL, fail if missing
#
# Works with GCC/Clang on Linux and with MinGW (run from Git Bash / MSYS).
set -euo pipefail
cd "$(dirname "$0")"

CXX=${CXX:-g++}
CXXFLAGS=${CXXFLAGS:-"-O3 -std=c++17 -Wall -Wextra"}
mode=${1:-auto}
EXE=""
case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) EXE=".exe";; esac
# On Windows/MinGW, statically link the GCC runtime so the .exe is
# self-contained (otherwise it needs libstdc++/libgcc/libwinpthread on PATH).
[ -n "$EXE" ] && CXXFLAGS="$CXXFLAGS -static"

echo "building nidhunt${EXE} (CPU)"
$CXX $CXXFLAGS -pthread src/nidhunt.cpp -o "nidhunt${EXE}"

build_gpu() {
    local link="$1"
    echo "building nidhunt-gpu${EXE} (CPU + GPU)"
    $CXX $CXXFLAGS -pthread -DNIDHUNT_OPENCL -Isrc src/nidhunt.cpp $link -o "nidhunt-gpu${EXE}"
}

if [ "$mode" = cpu ]; then
    exit 0
fi

# Figure out how to link the OpenCL loader.
link=""
if [ -n "$EXE" ]; then
    # MinGW on Windows: link the ICD loader DLL directly.
    for dll in "${SYSTEMROOT:-/c/Windows}/System32/OpenCL.dll" /c/Windows/System32/OpenCL.dll; do
        [ -f "$dll" ] && { link="$dll"; break; }
    done
    [ -z "$link" ] && link="-lOpenCL"
else
    link="-lOpenCL"
fi

if build_gpu "$link" 2>/tmp/nidhunt_gpu_build.log; then
    :
else
    cat /tmp/nidhunt_gpu_build.log
    if [ "$mode" = gpu ]; then
        echo "GPU build failed (OpenCL SDK/loader not found)" >&2
        exit 1
    fi
    echo "OpenCL not available; built CPU binary only" >&2
fi
