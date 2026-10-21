/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef PIV_CONTROL_H
#define PIV_CONTROL_H
#include <linux/ioctl.h>
#include <linux/types.h>
/* Experimental ABI. No primary key export; logical primary I/O is privileged. */
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
#define PIV_QUERY_LOWER_WRITE 1
#define PIV_QUERY_PRIMARY_FILTER 2
#define PIV_QUERY _IOR('P', 0, struct piv_query)
/* One authenticated carrier IV. Input iv/reserved must be zero. */
struct piv_read_iv {
	__u32 version;
	__u32 size;
	__u64 generation;
	__u64 sector; /* encryption-sector index */
	__u8 iv[16];
	__u32 reserved[2];
};
#define PIV_READ_IV _IOWR('P', 1, struct piv_read_iv)
#define PIV_QUERY_MUTATION 4
#define PIV_CONTROL_VERSION 2
#define PIV_TUPLE_BYTES 4128
struct piv_update {
	__u32 version;
	__u32 size;
	__u64 generation;
	__u64 sector;
	__u8 expected_iv[16];
	__u32 flags;
	__u8 tuple[PIV_TUPLE_BYTES]; /* sector ciphertext, zero-pad to 4096 || tag16 || IV16 (RAM ABI only) */
	__u32 reserved;
};
#define PIV_READ_QUIESCED _IOWR('P', 2, struct piv_read_iv)
#define PIV_PREPARE _IOWR('P', 3, struct piv_update)
#define PIV_APPLY _IOW('P', 4, struct piv_update)
#define PIV_BEGIN _IOW('P', 5, struct piv_read_iv)
#define PIV_END _IOW('P', 6, struct piv_read_iv)
struct piv_devices {
	__u32 owner_major, owner_minor, lower_major, lower_minor;
};
#define PIV_DEVICES _IOR('P', 7, struct piv_devices)
#define PIV_SYNC _IOW('P', 8, struct piv_read_iv)
#define PIV_APPLY_DEFER_FLUSH 1
/* Coordinated primary I/O. Raw primary bios remain filtered. */
#define PIV_QUERY_PRIMARY_CONTROL 8
#define PIV_READ_PRIMARY _IOWR('P', 9, struct piv_update)
#define PIV_PREPARE_PRIMARY _IOWR('P', 10, struct piv_update)
#define PIV_APPLY_PRIMARY _IOW('P', 11, struct piv_update)
/* Native SETUP ABI version 4 (2026-10-21): format v4 only (AEGIS-128). */
struct piv_native_setup {
 __u32 version, size;
 __u64 generation;
 __u32 flags, context_length; /* see PIV_SETUP_*; context = v4 base context */
 __u8 key[32], context[128];   /* key: keyslot KEK */
 __u32 reserved[2];
};
struct piv_native_status {
 /* invalidations: always 0 since v3 invalid markers were removed (ABI kept). */
 __u64 generation, hidden_bytes, encryptions, invalidations;
 __u32 active, views, failed, version;
};
/* Destructively initialize: new master key, keyslot 0 under the KEK, the
 * directory, then authenticated zeros in every hidden block. Without it, a
 * keyslot must authenticate under the KEK or setup returns EKEYREJECTED.
 */
#define PIV_SETUP_INITIALIZE 1U
/* With INITIALIZE: A/B record slots (atomic per-block hidden writes, half capacity). */
#define PIV_SETUP_AB 8U
#define PIV_NATIVE_SETUP _IOW('P', 12, struct piv_native_setup)
#define PIV_NATIVE_DETACH _IOW('P', 13, struct piv_read_iv)
#define PIV_NATIVE_STATUS _IOR('P', 14, struct piv_native_status)
/* v4 keyslot management on an active owner (version 1, 64 bytes). */
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
