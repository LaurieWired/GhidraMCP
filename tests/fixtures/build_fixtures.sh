#!/usr/bin/env bash
# Rebuilds the integration-test fixtures using the zig toolchain from PyPI (no system install).
set -euo pipefail
cd "$(dirname "$0")"

zigcc() {
    uvx --from ziglang python -m ziglang cc "$@"
}

zigcc -target x86_64-linux-gnu -O1 -g0 -fno-inline -o sample_x86_64.elf sample.c
zigcc -target x86_64-windows-gnu -O1 -g0 -fno-inline -o sample_x86_64.exe sample.c
ls -l sample_x86_64.elf sample_x86_64.exe
rm -f ./*.pdb ./*.lib
