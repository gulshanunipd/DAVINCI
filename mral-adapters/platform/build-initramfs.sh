#!/usr/bin/env bash
# Build the normal-world initramfs for the emulated Arm platform.
#   build-initramfs.sh <out.cpio.gz> [profile]
# profile "tampered-kernel" adds an unauthorised binary to the boot image; it
# changes the measured initramfs (PCR 9) and must be caught by the verifier.
set -euo pipefail
OUT="$1"
PROFILE="${2:-good}"
SRC="$(cd "$(dirname "$0")/.." && pwd)/optee-adapter"
R="$(mktemp -d)"
trap 'rm -rf "$R"' EXIT

mkdir -p "$R"/{bin,sbin,etc,proc,sys,dev,tmp,data,usr/bin,www/cgi-bin,lib/optee_armtz}
cp /bin/busybox "$R/bin/busybox"
for a in $(/bin/busybox --list); do
  [ "$a" = busybox ] || ln -sf busybox "$R/bin/$a"
done

cp "$(command -v tee-supplicant)" "$R/usr/bin/"
cp /opt/davinci/bin/davinci-attest "$R/usr/bin/"
for b in "$R/usr/bin/tee-supplicant" "$R/usr/bin/davinci-attest"; do
  for l in $(ldd "$b" | grep -o '/[^ ]*'); do
    mkdir -p "$R$(dirname "$l")"
    cp -L "$l" "$R$l"
  done
done

install -m 0755 "$SRC/guest/init" "$R/init"
install -m 0755 "$SRC/guest/attest.cgi" "$R/www/cgi-bin/attest"

if [ "$PROFILE" = "tampered-kernel" ]; then
  # Inert stand-in for a rootkit dropped into the boot image: it only marks its
  # presence, but any change to the boot image changes the measurement.
  printf '#!/bin/sh\n# unauthorised component (demo implant)\necho implant > /tmp/.implant\n' > "$R/sbin/implant"
  chmod +x "$R/sbin/implant"
  sed -i 's|^tee-supplicant |/sbin/implant \&\ntee-supplicant |' "$R/init"
fi

# Reproducible archive: fixed mtimes, sorted entries, no gzip timestamp, so the
# PCR 9 reference value is stable across rebuilds.
find "$R" -exec touch -h -d @0 {} +
(cd "$R" && find . | LC_ALL=C sort | cpio -o -H newc --reproducible 2>/dev/null | gzip -n -9) > "$OUT"
