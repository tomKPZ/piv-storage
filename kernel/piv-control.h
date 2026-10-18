/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef PIV_CONTROL_H
#define PIV_CONTROL_H
#include <linux/ioctl.h>
#include <linux/types.h>
/* Experimental ABI. No key or primary plaintext export. */
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
	__u8 iv[12];
	__u32 reserved[3];
};
#define PIV_READ_IV _IOWR('P', 1, struct piv_read_iv)
#endif
