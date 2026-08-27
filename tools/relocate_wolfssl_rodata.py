# TLS-env-only (nodemcuv2_tls) post: extra_script.
#
# Moves libwolfssl.a's .rodata out of DRAM into flash (irom0.text) by patching the
# GENERATED linker script $BUILD_DIR/ld/local.eagle.app.v6.common.ld (never the framework
# copy). Why: wolfSSL contributes ~26KB of .rodata; on the ESP8266 .rodata lives in
# dram0_0_seg, so even after the -2.6KB .bss shrink the TLS image left only ~1.2KB of
# boot heap -> SDK init OOMs pre-setup() and the node reset-loops (72x rst cause:2,
# zero readable output). Flash-resident rodata is safe here: the non32xfer exception
# handler is active in this build (MMU_IRAM_HEAP + NONOSDK 2.2.x), so 8/16-bit reads
# from irom work, just slowly - acceptable for the TLS PoC measurement path.
#
# Idempotent; touches ONLY builds that include this script (the TLS env). Reversal:
# remove the extra_scripts line from [env:nodemcuv2_tls] (generated ld regenerates clean).

Import("env")
import os

MARKER = "*libwolfssl.a:(.rodata .rodata.* .rodata1)"
ANCHOR = "*libbearssl.a:(.literal .text .literal.* .text.*)"


def patch_ld(path):
    if not os.path.isfile(path):
        return False
    with open(path, "r") as f:
        content = f.read()
    if MARKER in content:
        print("[wolfssl-rodata] ld already patched: %s" % path)
        return True
    if ANCHOR not in content:
        print("[wolfssl-rodata] ERROR: anchor not found in %s - NOT patched" % path)
        return False
    content = content.replace(ANCHOR, ANCHOR + "\n    " + MARKER, 1)
    with open(path, "w") as f:
        f.write(content)
    print("[wolfssl-rodata] patched %s (wolfSSL .rodata -> irom0.text)" % path)
    return True


ld_path = os.path.join(env.subst("$BUILD_DIR"), "ld", "local.eagle.app.v6.common.ld")

# Case 1: ld already generated in a previous build (env.Command is cached) - patch now.
patch_ld(ld_path)


# Case 2: ld (re)generated this build - patch right after generation, before link.
def _post_generate(target, source, env):
    patch_ld(str(target[0]))


env.AddPostAction(os.path.join("$BUILD_DIR", "ld", "local.eagle.app.v6.common.ld"), _post_generate)
