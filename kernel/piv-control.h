/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef PIV_CONTROL_H
#define PIV_CONTROL_H
#include <linux/ioctl.h>
#include <linux/types.h>
/* Experimental ABI. No primary key export; no userspace IV or tuple access. */
struct piv_query {
	__u32 version;
	__u32 size;
	__u64 generation;
	__u64 sectors; /* encryption sectors, not 512-byte addresses */
	__u32 sector_size;
	__u32 iv_size;
	__u32 tag_size;
	__u32 tuple_size;
	__u32 flags;
	__u32 reserved;
};
#define PIV_QUERY _IOR('P', 0, struct piv_query)
#define PIV_CONTROL_VERSION 2
/* Request header for BEGIN/END/DETACH: version, size and generation must
 * match; sector, iv and reserved must be zero. (Numbers 1-4 and 8-11, the
 * former userspace IV read and prepare/apply controls, were removed on
 * 2026-10-22; they return ENOTTY. The owner's internal prepare/apply path is
 * unchanged.)
 */
struct piv_read_iv {
	__u32 version;
	__u32 size;
	__u64 generation;
	__u64 sector;
	__u8 iv[16];
	__u32 reserved[2];
};
#define PIV_BEGIN _IOW('P', 5, struct piv_read_iv)
#define PIV_END _IOW('P', 6, struct piv_read_iv)
struct piv_devices {
	__u32 owner_major, owner_minor, lower_major, lower_minor;
};
#define PIV_DEVICES _IOR('P', 7, struct piv_devices)
/* Native SETUP ABI version 6 (2026-10-22): format v5 only. Version 6 added
 * QUICK and FILL and the FILL output counts (read/write ioctl; the kernel
 * copies the request back with the key zeroed after a successful setup).
 */
struct piv_native_setup {
 __u32 version, size;
 __u64 generation;
 __u32 flags, context_length; /* see PIV_SETUP_*; context = v5 base context */
 __u8 key[32], context[128];   /* key: keyslot KEK */
 __u32 parity;                 /* RS parity fragments per lane: 0, 4, 8, 16; INITIALIZE only */
 __u32 reserved;
 /* Output (zero on input), FILL only: blocks whose record already
  * authenticated (skipped), blocks given a zero record, and blocks left as
  * they were because their carrier could not be read or authenticated.
  */
 __u64 valid, written, failed;
};
/* STATUS version 4 (2026-10-22): the always-zero v3 invalidations field was removed. */
struct piv_native_status {
 __u64 generation, hidden_bytes, encryptions;
 __u32 active, views, failed, version;
};
/* Destructively initialize: new master key, keyslot 0 under the KEK (with
 * the A/B flag and the parity), the directory, then authenticated zeros in
 * every 4096-byte hidden block (unless QUICK). Without it, a
 * keyslot must authenticate under the KEK or setup returns EKEYREJECTED.
 */
#define PIV_SETUP_INITIALIZE 1U
/* With INITIALIZE: A/B record slots (atomic per-block hidden writes, half capacity). */
#define PIV_SETUP_AB 8U
/* Full audit: authenticate every primary sector and refuse on any failure.
 * Without it setup scans only the keyslot area (constant time); requests
 * still authenticate every sector they touch.
 */
#define PIV_SETUP_VERIFY 16U
/* With INITIALIZE: write only keyslot 0 and the directory. Never-written
 * hidden blocks do not authenticate (reads return EIO) until written or filled.
 */
#define PIV_SETUP_QUICK 32U
/* Without INITIALIZE, after the keyslot and directory authenticate: give every
 * hidden block whose record does not authenticate under the master key a
 * zero record (A/B: slot 0, generation 1); authenticated blocks are skipped.
 * Completes a quick or interrupted initialization and resumes itself.
 * Destructive: damaged blocks become zeros. Never implied by another flag.
 */
#define PIV_SETUP_FILL 64U
#define PIV_NATIVE_SETUP _IOWR('P', 12, struct piv_native_setup)
#define PIV_NATIVE_DETACH _IOW('P', 13, struct piv_read_iv)
#define PIV_NATIVE_STATUS _IOR('P', 14, struct piv_native_status)
/* v5 keyslot management on an active owner (version 1, 64 bytes). */
struct piv_native_keyslot {
 __u32 version, size;
 __u64 generation;
 __u32 slot, op;
 __u8 kek[32];
 __u32 reserved[2];
};
#define PIV_KEYSLOT_ADD 1U
#define PIV_KEYSLOT_REMOVE 2U
#define PIV_NATIVE_KEYSLOT _IOW('P', 15, struct piv_native_keyslot)
#endif
