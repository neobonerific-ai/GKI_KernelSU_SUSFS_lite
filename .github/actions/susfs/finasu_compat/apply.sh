#!/usr/bin/env bash
# FinaSU native SUSFS integration verification (no legacy 10_enable patch).
# FinaSU v1.3.2+ ships SUSFS natively; applying 10_enable_susfs_for_ksu.patch
# on top would double-patch and break the build. This script only verifies that
# the native integration is present and consistent.
set -euo pipefail

KSU_DIR="${1:-FinaSU}"
KERNEL_ROOT="${KERNEL_ROOT:-$PWD}"
KSU_ROOT="$KERNEL_ROOT/$KSU_DIR"

fail() { echo "::error::$*" >&2; exit 1; }

[ -d "$KSU_ROOT" ] || fail "$KSU_DIR not found at $KSU_ROOT"

# Native SUSFS sources must exist.
for f in kernel/extension/susfs.c kernel/feature/selinux_hide.c kernel/Kbuild kernel/Kconfig kernel/core/init.c; do
  [ -f "$KSU_ROOT/$f" ] || fail "missing native SUSFS file: $KSU_DIR/$f"
done

# Native integration markers in Kbuild.
grep -q 'kernelsu-$(CONFIG_KSU_SUSFS) += extension/susfs.o' "$KSU_ROOT/kernel/Kbuild" \
  || fail "FinaSU Kbuild lacks native SUSFS object entry"

# Kconfig entry
grep -qi 'susfs' "$KSU_ROOT/kernel/Kconfig" \
  || fail "FinaSU Kconfig lacks SUSFS option"

# init.c calls susfs_init
grep -q 'susfs_init' "$KSU_ROOT/kernel/core/init.c" \
  || fail "FinaSU core/init.c lacks susfs_init() call"

# KALLSYMS_ALL guard must be present (v1.3.1+ built-in requirement).
grep -q 'CONFIG_KALLSYMS_ALL' "$KSU_ROOT/kernel/Kbuild" \
  || fail "FinaSU Kbuild missing CONFIG_KALLSYMS_ALL guard"

# Ensure no leftover 10_enable artifacts.
if [ -f "$KSU_ROOT/10_enable_susfs_for_ksu.patch" ]; then
  rm -f "$KSU_ROOT/10_enable_susfs_for_ksu.patch"
fi

echo "FinaSU native SUSFS integration verified (no legacy patches applied)."
