// SPDX-License-Identifier: GPL-2.0-only
/* Guest-only cross-check harness: the dm-piv Reed-Solomon code
 * (kernel/piv-rs.inc, compiled unchanged) as a freestanding shared object
 * that kernel/guest-v5-test.py loads with ctypes and compares against
 * pivstore/rs.py and pivstore/records.py. The guest has a compiler but no libc
 * headers, so nothing here includes system headers. Never linked into dm-piv
 * and never loaded on the host.
 *
 *   gcc-14 -O2 -Wall -Werror -shared -fPIC -nostdlib -ffreestanding \
 *          -fno-tree-loop-distribute-patterns -o piv-rs-test.so piv-rs-test.c
 */
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long size_t;
#if __STDC_VERSION__ < 202311L
typedef _Bool bool;
#define true 1
#endif
#define BITS_PER_LONG (8 * sizeof(long))
#define BITS_TO_LONGS(n) (((n) + BITS_PER_LONG - 1) / BITS_PER_LONG)

void *memset(void *p, int c, size_t n)
{
	u8 *d = p;
	while (n--) *d++ = (u8)c;
	return p;
}

void *memmove(void *to, const void *from, size_t n)
{
	u8 *d = to;
	const u8 *s = from;
	if (d < s) while (n--) *d++ = *s++;
	else while (n--) d[n] = s[n];
	return to;
}

void *memcpy(void *to, const void *from, size_t n) { return memmove(to, from, n); }

static bool test_bit(u32 bit, const unsigned long *map) { return map[bit / BITS_PER_LONG] >> (bit % BITS_PER_LONG) & 1; }
static void memzero_explicit(void *p, size_t n) { memset(p, 0, n); __asm__ volatile("" : : "r"(p) : "memory"); }

#define PN_FRAGMENT 6
#define PN_DATA_FRAGMENTS 687
#define PN_LANES 3
#define PN_LANE_DATA (PN_DATA_FRAGMENTS / PN_LANES)
#define PN_MAX_PARITY 16
#define PN_MAX_GROUP (PN_DATA_FRAGMENTS + PN_LANES * PN_MAX_PARITY)
#include "piv-rs.inc"

static bool ready;

/* 3p parity fragments of the 687 data fragments in @payload. */
void piv_rs_test_parity(const u8 *payload, u32 p, u8 *parity)
{
	if (!ready) { pn_gf_init(); ready = true; }
	pn_rs_parity(payload, p, parity);
}

/* Correct @fragments (687 + 3p) in place; @flags[j] != 0 marks fragment j
 * erased. Returns 0 on success, -1 when uncorrectable.
 */
int piv_rs_test_correct(u8 *fragments, u32 p, const u8 *flags)
{
	unsigned long erased[BITS_TO_LONGS(PN_MAX_GROUP)] = {0};
	u32 j;
	if (!ready) { pn_gf_init(); ready = true; }
	for (j = 0; j < PN_DATA_FRAGMENTS + PN_LANES * p; j++)
		if (flags[j]) erased[j / BITS_PER_LONG] |= 1UL << (j % BITS_PER_LONG);
	return pn_rs_correct(fragments, p, erased);
}
