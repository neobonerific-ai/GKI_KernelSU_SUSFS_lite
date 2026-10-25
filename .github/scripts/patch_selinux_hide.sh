#!/usr/bin/env bash
set -euo pipefail
cd "${GITHUB_WORKSPACE:-.}/kernel"

# 1. Expose selinux_setprocattr in kallsyms
if [ -f common/security/selinux/hooks.c ]; then
  sed -i 's/^static int selinux_setprocattr(/int selinux_setprocattr(/' common/security/selinux/hooks.c
  echo "Patched hooks.c"
fi

python3 - <<'PY'
import os, re
ksu_dirs = [d for d in ["KernelSU/kernel", "KernelSU-Next/kernel", "drivers/kernelsu"] if os.path.isdir(d)]
if ksu_dirs:
    ksu_dir = ksu_dirs[0]
    print("KSU dir:", ksu_dir)

    # backup_sepolicy guard (search all rules.c)
    for root,_,files in os.walk(ksu_dir):
        for fn in files:
            if fn == "rules.c" and "selinux" in root:
                p = os.path.join(root,fn)
                with open(p) as f: c=f.read()
                target="backup_sepolicy = ksu_dup_sepolicy("
                if "if (!backup_sepolicy)" not in c and target in c:
                    c=c.replace(target,"if (!backup_sepolicy)\n\t\tbackup_sepolicy = ksu_dup_sepolicy(",1)
                    with open(p,"w") as f: f.write(c)
                    print("Patched backup_sepolicy guard in",p)

    # LTO $ suffix support (all C files)
    for root,_,files in os.walk(ksu_dir):
        for fn in files:
            if not fn.endswith(".c"): continue
            p=os.path.join(root,fn)
            with open(p) as f: c=f.read()
            if '".llvm."' in c:
                c_new=c.replace('strncmp(name + len, ".llvm.", 6) == 0',
                                'strncmp(name + len, ".llvm.", 6) == 0 || name[len] == \'$\'')
                if c_new!=c:
                    with open(p,"w") as f: f.write(c_new)
                    print("Patched $ LTO symbol handling in",p)

    # selinux_hide: never tear down selinuxfs hooks (search by filename)
    for root,_,files in os.walk(ksu_dir):
        for fn in files:
            if fn != "selinux_hide.c": continue
            p=os.path.join(root,fn)
            with open(p) as f: c=f.read()
            orig=c
            c=c.replace("goto err_setprocattr;","ret = 0; /* keep selinuxfs hooks alive */")
            c=re.sub(r'if \(ret\) \{\s*\n\s*pr_err\("init: selinux_setprocattr_hook err: %d\\n", ret\);\s*\n\s*goto err_setprocattr;\s*\n\s*\}',
                     'if (ret) {\n\t\tpr_warn("init: selinux_setprocattr_hook err: %d (continuing with selinuxfs hooks)\\n", ret);\n\t\tret = 0;\n\t}', c)
            if c!=orig:
                with open(p,"w") as f: f.write(c)
                print("Patched selinux_hide.c to keep selinuxfs hooks alive:",p)
            else:
                print("selinux_hide.c found but no pattern matched:",p)
    # lsm_hook: robust hlist match by address range (CFI/LTO)
    for root,_,files in os.walk(ksu_dir):
        for fn in files:
            if fn != "lsm_hook.c": continue
            p=os.path.join(root,fn)
            with open(p) as f: c=f.read()
            orig=c
            helper='''static bool ksu_lsm_origin_in_target(void *origin, void *target) {
    unsigned long size = 0;
    if (origin == target)
        return true;
    if (!kallsyms_lookup_size_offset((unsigned long)target, &size, NULL) || !size)
        size = 1;
    return origin >= target && (unsigned long)origin < (unsigned long)target + size;
}

'''
            if "ksu_lsm_origin_in_target" not in c:
                c=c.replace("int ksu_lsm_hook(struct ksu_lsm_hook *hook)", helper+"int ksu_lsm_hook(struct ksu_lsm_hook *hook)",1)
            c=c.replace("if (current_origin == target) {", "if (ksu_lsm_origin_in_target(current_origin, target)) {")
            if c!=orig:
                with open(p,"w") as f: f.write(c)
                print("Patched lsm_hook.c range match:",p)
            else:
                print("lsm_hook.c found but no change:",p)
PY