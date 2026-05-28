#!/bin/bash

export ARCH=arm64
export SUBARCH=arm64
export KBUILD_BUILD_USER="linex"
export KBUILD_BUILD_HOST="Project"

OUT_DIR="out"
mkdir -p $OUT_DIR

if [ ! -f "$OUT_DIR/.config" ]; then
    echo "--- 🛠️ Merging Config ---"
    DEFCONFIG="vendor/xiaomi/mi845_defconfig"
    FRAGS="arch/arm64/configs/vendor/xiaomi/beryllium.config arch/arm64/configs/vendor/xiaomi/limitless.config"
    ./scripts/kconfig/merge_config.sh -O $OUT_DIR arch/arm64/configs/$DEFCONFIG $FRAGS
    make O=$OUT_DIR CC=clang LLVM=1 olddefconfig
else
    # rm -rf out
    rm -f $OUT_DIR/.version $OUT_DIR/include/generated/compile.h $OUT_DIR/init/version.o $OUT_DIR/arch/arm64/boot/Image.gz-dtb
fi

K_FLAGS="-fcommon -Qunused-arguments -Wno-everything"
make -j$(nproc --all) O=$OUT_DIR \
    CC=clang \
    LD=ld.lld \
    LD_GOLD=ld.lld \
    AR=llvm-ar \
    NM=llvm-nm \
    OBJCOPY=llvm-objcopy \
    OBJDUMP=llvm-objdump \
    STRIP=llvm-strip \
    LLVM=1 \
    LLVM_IAS=1 \
    KCFLAGS="$K_FLAGS" \
    EXTRA_CFLAGS="$K_FLAGS" \
    CLANG_TRIPLE=aarch64-linux-gnu- \
    CROSS_COMPILE=aarch64-linux-gnu- \
    CROSS_COMPILE_ARM32=arm-linux-gnueabi-
