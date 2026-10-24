#!/usr/bin/env bash
set -euo pipefail
cd "${GITHUB_WORKSPACE:-.}/kernel"

# 1. Expose selinux_setprocattr in kallsyms
if [ -f common/security/selinux/hooks.c ]; then
  sed -i 's/^static int selinux_setprocattr(/int selinux_setprocattr(/' common/security/selinux/hooks.c
  echo "Patched hooks.c"
fi

python3 - <<'PY'
import os, glob
ksu_dirs = [d for d in ["KernelSU/kernel", "KernelSU-Next/kernel", "drivers/kernelsu"] if os.path.isdir(d)]
if ksu_dirs:
    ksu_dir = ksu_dirs[0]
    rules_path = os.path.join(ksu_dir, "selinux/rules.c")
    if os.path.isfile(rules_path):
        with open(rules_path) as f:
            c = f.read()
        target = "backup_sepolicy = ksu_dup_sepolicy("
        if "if (!backup_sepolicy)" not in c and target in c:
            c = c.replace(target, "if (!backup_sepolicy)\n\t\tbackup_sepolicy = ksu_dup_sepolicy(", 1)
            with open(rules_path, "w") as f:
                f.write(c)
            print("Patched backup_sepolicy guard in rules.c")
    for p in glob.glob(os.path.join(ksu_dir, "**/*.c"), recursive=True):
        with open(p) as f:
            c = f.read()
        if '".llvm."' in c:
            c_new = c.replace(
                'strncmp(name + len, ".llvm.", 6) == 0',
                'strncmp(name + len, ".llvm.", 6) == 0 || name[len] == \'$\''
            )
            if c_new != c:
                with open(p, "w") as f:
                    f.write(c_new)
                print(f"Patched $ LTO symbol handling in {p}")
    hide_path = os.path.join(ksu_dir, "feature/selinux_hide.c")
    if os.path.isfile(hide_path):
        with open(hide_path) as f:
            c = f.read()
        c_new = c.replace("goto err_setprocattr;", "ret = 0; /* keep selinuxfs hooks alive */")
        if c_new != c:
            with open(hide_path, "w") as f:
                f.write(c_new)
            print("Patched selinux_hide.c to keep selinuxfs hooks alive")
PY
