#!/bin/bash
# Deployment test, phase 1 (scripts/suite.py "deploy"): install pivsetup, the
# DKMS module and the initramfs-tools integration with packaging/install.sh,
# check the DKMS signature, activate from the installed pieces, build an
# initramfs that opens the views at boot (embed-keys, synthetic test keys
# only), then request a reboot of the same disks (scripts/guest-deploy-boot.sh).
# /dev/vdb is the closed native fixture.
source /mnt/piv-work/guest-common.sh
guest_packages linux-headers-6.12.113+deb13-amd64=6.12.113-1 gcc-14 make dkms=3.2.2-1~deb13u1
guest_code
fail() { echo "DEPLOY FAIL: $*" >&2; exit 1; }
release=$(uname -r)
mkdir -p /root/piv-src /root/piv-packaging
tar -xf scaffold.tar -C /root/piv-src
tar -xf packaging.tar -C /root/piv-packaging
P=/root/piv-packaging/packaging

# pivsetup: the installed binary is the host-built static release binary
# (no PIVSETUP_TEST_* hooks); install.sh refuses the test-hooks build.
rm -f /usr/local/sbin/pivsetup
if bash "$P/install.sh" pivsetup /mnt/piv-work/pivsetup 2> install-hooks.err; then
    fail "install.sh accepted the test-hooks build"
fi
grep -q 'not a release build' install-hooks.err || { cat install-hooks.err; fail "test-hooks refusal message"; }
bash "$P/install.sh" pivsetup /mnt/piv-work/pivsetup-release
cmp /usr/local/sbin/pivsetup /mnt/piv-work/pivsetup-release
file_type=$(od -An -c -N4 /usr/local/sbin/pivsetup | tr -d ' ')
test "$file_type" = '177ELF'
/usr/local/sbin/pivsetup --version > pivsetup-version.txt
grep -qx "pivsetup $(cat "$P/VERSION")" pivsetup-version.txt || fail "pivsetup version"
grep -qx 'test hooks: no' pivsetup-version.txt || fail "release build has test hooks"
grep -q '^control ABI: QUERY 2, request 2, SETUP 6, STATUS 4, KEYSLOT 2$' pivsetup-version.txt || fail "ABI versions"
version=$(cat "$P/VERSION")

# DKMS: build, install and sign (DKMS generates a throwaway MOK key pair in
# /var/lib/dkms inside this disposable guest).
bash "$P/install.sh" dkms /root/piv-src > dkms-install.log 2>&1 || { cat dkms-install.log; fail dkms; }
dkms status > dkms-status.txt
grep -q "^dm-piv/$version, $release, x86_64: installed" dkms-status.txt || fail "dkms status"
module=$(modinfo -n dm-piv)
case "$module" in /lib/modules/"$release"/updates/dkms/dm-piv.ko*) ;; *) fail "module path $module" ;; esac
modinfo dm-piv > deploy-modinfo.txt
test -n "$(modinfo -F signer dm-piv)" || fail "unsigned DKMS module"
test -e /var/lib/dkms/mok.pub || fail "no DKMS signing certificate"
# Verify the appended PKCS#7 signature against the DKMS certificate.
python3 - "$module" <<'PY'
import lzma, struct, subprocess, sys
data = open(sys.argv[1], 'rb').read()
if sys.argv[1].endswith('.xz'):
    data = lzma.decompress(data)
elif sys.argv[1].endswith('.zst'):
    data = subprocess.run(['zstd', '-dc', sys.argv[1]], capture_output=True, check=True).stdout
magic = b'~Module signature appended~\n'
assert data.endswith(magic), 'no appended module signature'
info = data[-len(magic) - 12:-len(magic)]
sig_len = struct.unpack('>I', info[8:12])[0]
assert info[2] == 2, 'signature is not PKCS#7'
body_end = len(data) - len(magic) - 12 - sig_len
open('/run/piv-module.body', 'wb').write(data[:body_end])
open('/run/piv-module.p7s', 'wb').write(data[body_end:body_end + sig_len])
PY
openssl x509 -inform DER -in /var/lib/dkms/mok.pub -out /run/piv-mok.pem
openssl cms -verify -binary -inform DER -in /run/piv-module.p7s -content /run/piv-module.body \
    -certfile /run/piv-mok.pem -nointern -noverify -out /dev/null 2> module-signature.txt ||
    { cat module-signature.txt; fail "module signature"; }
cat module-signature.txt
openssl x509 -in /run/piv-mok.pem -noout -subject -fingerprint -sha256 > dkms-mok.txt

# Activate from the installed module and binary (not insmod of a build tree).
modprobe dm_integrity
modprobe dm_crypt
guest_stock_live_start
modprobe dm-piv
test -d /sys/module/dm_piv
guest_stock_live_check
# Key files must be root-owned and private: the 9p share's are refused (the
# release build ignores PIVSETUP_TEST_LAX_KEY_FILES, exported by guest-common).
test "$PIVSETUP_TEST_LAX_KEY_FILES" = 1
if /usr/local/sbin/pivsetup open-blocks --device /dev/vdb --key-file passphrase.key \
        --hidden-key-file hidden.key > /dev/null 2> key-mode.err; then
    fail "accepted key files on the 9p share"
fi
grep -qE 'Key file .* (is not owned by root|is accessible by group or others)' key-mode.err ||
    { cat key-mode.err; fail "key-file refusal message"; }
install -d -m 0700 /etc/piv
install -m 0600 passphrase.key /etc/piv/passphrase.key
install -m 0600 hidden.key /etc/piv/hidden.key
install -m 0644 hidden.key /var/tmp/piv-readable.key
if /usr/local/sbin/pivsetup open-blocks --device /dev/vdb --key-file /etc/piv/passphrase.key \
        --hidden-key-file /var/tmp/piv-readable.key > /dev/null 2> key-mode.err; then
    fail "accepted a world-readable hidden key file"
fi
grep -q 'is accessible by group or others' key-mode.err || { cat key-mode.err; fail "key-file mode message"; }
rm -f /var/tmp/piv-readable.key
# PIVSETUP_TEST_FAIL is ignored by the release build (the test build fails here).
PIVSETUP_TEST_FAIL=before-setup /usr/local/sbin/pivsetup open-blocks --device /dev/vdb \
    --key-file /etc/piv/passphrase.key --hidden-key-file /etc/piv/hidden.key > deploy-open.json
cmp /dev/mapper/piv-native-hidden expected-hidden-volume
test "$(sha256sum /dev/mapper/piv-native-decoy | cut -d ' ' -f 1)" = "$(cat expected-primary.sha256)"
/usr/local/sbin/pivsetup close-blocks --device /dev/vdb --key-file /etc/piv/passphrase.key

# initramfs-tools integration.
bash "$P/install.sh" initramfs
# Invalid configurations make mkinitramfs fail with the hook's message.
negative() {
    printf '%s\n' "$1" > /etc/pivtab
    if mkinitramfs -o /var/tmp/piv-negative.img "$release" 2> /var/tmp/piv-negative.err; then
        fail "accepted invalid pivtab: $1"
    fi
    grep -q "E: pivsetup hook: .*$2" /var/tmp/piv-negative.err || { cat /var/tmp/piv-negative.err; fail "message for: $1"; }
    rm -f /var/tmp/piv-negative.img
}
negative 'piv-native /dev/vdb /etc/piv/passphrase.key /etc/piv/hidden.key -' 'would not exist at boot'
negative 'piv-native /dev/vdb ask ask -' 'cannot be typed'
negative 'native /dev/vdb ask ask hidden-passphrase' 'invalid mapping name'
negative 'piv-native /dev/vdb ask ask hidden-passphrase,bogus' 'unknown option'
negative 'piv-native vdb ask ask hidden-passphrase' 'must be a /dev path'
negative 'piv-native /dev/vdb /etc/piv/missing.key /etc/piv/hidden.key embed-keys' 'not a readable regular file'
# embed-keys needs the private-image configuration (UMASK=0077).
mv /etc/initramfs-tools/conf.d/pivsetup /var/tmp/piv-conf
negative 'piv-native /dev/vdb /etc/piv/passphrase.key /etc/piv/hidden.key embed-keys' 'embed-keys needs UMASK=0077'
mv /var/tmp/piv-conf /etc/initramfs-tools/conf.d/pivsetup
printf 'piv-native /dev/vdb /etc/piv/passphrase.key /etc/piv/hidden.key embed-keys\n' > /etc/pivtab
update-initramfs -u -k "$release" > update-initramfs.log 2>&1 || { cat update-initramfs.log; fail update-initramfs; }
initrd=/boot/initrd.img-$release
test "$(stat -c %a "$initrd")" = 600 || fail "initramfs mode $(stat -c %a "$initrd")"
lsinitramfs "$initrd" > initramfs-list.txt
for entry in usr/sbin/pivsetup etc/pivtab etc/pivsetup/piv-native.luks etc/pivsetup/piv-native.hidden \
             scripts/local-top/pivsetup usr/sbin/cryptsetup usr/sbin/dmsetup; do
    grep -qx "$entry" initramfs-list.txt || fail "initramfs lacks $entry"
done
grep -q "updates/dkms/dm-piv.ko" initramfs-list.txt || fail "initramfs lacks the DKMS module"
mkdir /var/tmp/piv-initrd
unmkinitramfs "$initrd" /var/tmp/piv-initrd
root=/var/tmp/piv-initrd/main
test -d "$root" || root=/var/tmp/piv-initrd
cmp "$root/etc/pivsetup/piv-native.luks" passphrase.key
cmp "$root/etc/pivsetup/piv-native.hidden" hidden.key
cmp "$root/usr/sbin/pivsetup" /usr/local/sbin/pivsetup
grep -qx 'piv-native /dev/vdb /etc/pivsetup/piv-native.luks /etc/pivsetup/piv-native.hidden -' "$root/etc/pivtab"
rm -rf /var/tmp/piv-initrd
printf 'phase 1 passed\n' > deploy-phase1.txt
guest_record
sync
echo PIV_POWER_CUT
sleep 600
