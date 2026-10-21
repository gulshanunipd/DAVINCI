# DAVINCI attested platform: an emulated Arm v8 machine with two real Roots of
# Trust and their MRAL collectors.
#
#   RoT 1  TPM 2.0  — swtpm (software TPM), EK certified by the swtpm local CA.
#                     Collector: tpm-adapter/tpm_adapter.py           (:4010)
#   RoT 2  OP-TEE   — Arm TrustZone TEE (TF-A + OP-TEE OS 4.1 on QEMU virt,
#                     secure=on) with the attestation PTA.
#                     Collector: optee-adapter (TA + CA in the guest)  (:4020)
#   Harness         — platform/controller.py: measured boot + power cycle (:4000)
#
# Stages:
#   firmware  cross-compiles TF-A, OP-TEE OS, U-Boot, Linux and the TA on the
#             build host's native architecture (fast on x86-64 and arm64)
#   guest     arm64 normal-world userland (busybox, OP-TEE client, collector)
#             packed into the boot initramfs; on x86-64 hosts Docker runs this
#             small stage through QEMU user emulation (binfmt)
#   runtime   swtpm + QEMU + collectors, native to the host
# Everything is built from pinned upstream sources.

ARG UBUNTU=ubuntu:24.04

################################### firmware ###################################
FROM --platform=$BUILDPLATFORM ${UBUNTU} AS firmware
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu \
      git ca-certificates curl xz-utils python3 \
      python3-cryptography python3-pyelftools python3-setuptools python3-dev swig \
      device-tree-compiler bc bison flex libssl-dev libelf-dev libgnutls28-dev uuid-dev \
      && rm -rf /var/lib/apt/lists/*
WORKDIR /src
ENV CROSS_COMPILE=aarch64-linux-gnu-

# OP-TEE OS with the attestation PTA. ASLR is disabled so that the runtime
# memory hashes of the TEE core and of TAs are reproducible reference values.
RUN git clone -q --depth 1 -b 4.1.0 https://github.com/OP-TEE/optee_os.git && \
    make -C optee_os -j"$(nproc)" O=/out/optee \
      PLATFORM=vexpress-qemu_armv8a CFG_ARM64_core=y CFG_USER_TA_TARGETS=ta_arm64 \
      CROSS_COMPILE64=aarch64-linux-gnu- \
      CFG_ARM_GICV3=y CFG_ATTESTATION_PTA=y CFG_CORE_ASLR=n CFG_TA_ASLR=n

# U-Boot (BL33). The default load addresses collide with OP-TEE's static SHM
# and a large kernel, so the kernel/initrd are placed above them.
RUN git clone -q --depth 1 -b v2025.01 https://github.com/u-boot/u-boot.git && cd u-boot && \
    sed -i -e 's/^kernel_addr_r=.*/kernel_addr_r=0x42200000/' \
           -e 's/^ramdisk_addr_r=.*/ramdisk_addr_r=0x48000000/' board/emulation/qemu-arm/qemu-arm.env && \
    make -s qemu_arm64_defconfig && \
    ./scripts/config -d TOOLS_MKEFICAPSULE -e USE_BOOTCOMMAND \
      --set-str BOOTCOMMAND "bootflow scan -lb" --set-val BOOTDELAY 0 && \
    make -s olddefconfig && make -s -j"$(nproc)"

# Trusted Firmware-A (BL1/BL2/BL31) with the OP-TEE dispatcher.
RUN git clone -q --depth 1 -b v2.10.0 https://github.com/ARM-software/arm-trusted-firmware.git tfa && \
    make -C tfa -j"$(nproc)" PLAT=qemu SPD=opteed \
      ARM_TSP_RAM_LOCATION=tdram BL32_RAM_LOCATION=tdram QEMU_USE_GIC_DRIVER=QEMU_GICV3 \
      BL32=/out/optee/core/tee-header_v2.bin \
      BL32_EXTRA1=/out/optee/core/tee-pager_v2.bin \
      BL32_EXTRA2=/out/optee/core/tee-pageable_v2.bin \
      BL33=/src/u-boot/u-boot.bin all

# Normal-world Linux with the OP-TEE driver built in (SMC conduit, no FF-A).
RUN curl -sSfL https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.6.58.tar.xz | tar xJ && \
    cd linux-6.6.58 && make -s ARCH=arm64 defconfig && \
    ./scripts/config -e TEE -e OPTEE -d ARM_FFA_TRANSPORT -d DRM -d SOUND -d WLAN -d BT \
      -d MEDIA_SUPPORT -d USB_SUPPORT -d STAGING && \
    make -s ARCH=arm64 olddefconfig && make -s ARCH=arm64 -j"$(nproc)" Image

# DAVINCI workload TA: reference build and compromised variant.
COPY optee-adapter/ta /src/ta
RUN make -C /src/ta -s TA_DEV_KIT_DIR=/out/optee/export-ta_arm64 O=/out/ta-good && \
    make -C /src/ta -s TA_DEV_KIT_DIR=/out/optee/export-ta_arm64 O=/out/ta-rogue \
      EXTRA_CFLAGS=-DDAVINCI_BACKDOOR

RUN mkdir -p /fw /ta/good /ta/tampered && \
    cp tfa/build/qemu/release/bl1.bin tfa/build/qemu/release/bl2.bin tfa/build/qemu/release/bl31.bin /fw/ && \
    cp /out/optee/core/tee-header_v2.bin /fw/bl32.bin && \
    cp /out/optee/core/tee-pager_v2.bin /fw/bl32_extra1.bin && \
    cp /out/optee/core/tee-pageable_v2.bin /fw/bl32_extra2.bin && \
    cp u-boot/u-boot.bin /fw/bl33.bin && \
    cp linux-6.6.58/arch/arm64/boot/Image /fw/Image && \
    cp /out/ta-good/*.ta /ta/good/ && cp /out/ta-rogue/*.ta /ta/tampered/

############################ guest userland (arm64) ############################
FROM --platform=linux/arm64 ${UBUNTU} AS guest
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      gcc libc6-dev optee-client-dev tee-supplicant busybox-static cpio \
      && rm -rf /var/lib/apt/lists/*
COPY optee-adapter /opt/davinci/optee-adapter
COPY platform/build-initramfs.sh /opt/davinci/platform/build-initramfs.sh
RUN mkdir -p /opt/davinci/bin /out && \
    gcc -O2 -Wall -I/opt/davinci/optee-adapter/ta/include \
      /opt/davinci/optee-adapter/host/davinci_attest.c -lteec -o /opt/davinci/bin/davinci-attest && \
    /opt/davinci/platform/build-initramfs.sh /out/initramfs-good.cpio.gz good && \
    /opt/davinci/platform/build-initramfs.sh /out/initramfs-tampered-kernel.cpio.gz tampered-kernel

################################### runtime ####################################
FROM ${UBUNTU}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      swtpm swtpm-tools tpm2-tools qemu-system-arm python3 curl openssl ca-certificates \
      && rm -rf /var/lib/apt/lists/*

COPY --from=firmware /fw /opt/davinci/fw
COPY --from=firmware /ta /opt/davinci/ta
# Boot images per profile: "tampered-kernel" carries an implant in the measured
# initramfs; "tampered-ta" reuses the good image with the rogue TA.
COPY --from=guest /out/ /opt/davinci/fw/
COPY tpm-adapter /opt/davinci/tpm-adapter
COPY platform /opt/davinci/platform

VOLUME ["/var/lib/davinci", "/trust"]
EXPOSE 4000 4010 4020
CMD ["/opt/davinci/platform/start-platform.sh"]
