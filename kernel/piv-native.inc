/* SPDX-License-Identifier: GPL-2.0-only */
/* Stateless paired views over format v5 (docs/format-v5.md; 16-byte random IVs:
 * AEGIS-128 or XTS + HMAC). Only stock dm-integrity persists recovery information. Whole
 * hidden blocks authenticate, but interrupted multi-sector writes can destroy
 * them (A/B slots keep the previous version). View requests run concurrently
 * in NOIO context on an unbound workqueue under the owner's shared I/O lock;
 * requests touching the same sectors or hidden record serialize on range
 * locks (piv_range_lock).
 */
/* Positive internal sentinel: LOCAL hidden unavailability. -ENODATA may also
 * mean a block medium error and is never treated as unavailability.
 */
#define PN_UNAVAILABLE 1
/* Power-of-two DM split boundary: a decoy work item touches at most 256
 * primary sectors (128 KiB / 512). No cross-bio accumulation or delayed
 * completion is used.
 */
#define PN_DECOY_BYTES (128 * 1024)
#define PN_DECOY_ENTRIES (PN_DECOY_BYTES / 512)
/* Concurrent view requests (workqueue max_active, shared by all owners). It
 * bounds request memory: at most about 3 MiB per hidden write or read at
 * 4096-byte sectors.
 */
#define PN_MAX_ACTIVE 16
/* Initialization writes this many records concurrently per round, flushes
 * the lower device after every PN_INIT_FLUSH_RECORDS records (a multiple) and
 * before returning, also when cancelled. View writes flush only for FUA.
 */
#define PN_INIT_PARALLEL 8
#define PN_INIT_FLUSH_RECORDS 16
static_assert(PN_INIT_FLUSH_RECORDS % PN_INIT_PARALLEL == 0);
/* Format v5 (docs/format-v5.md), 16-byte IVs only: each primary IV carries
 * LRW-AES(r[10] || d[6]) with tweak = primary sector; one 4096-byte block is a
 * 4122-byte SIV payload in 687 fragments, followed by 3p Reed-Solomon parity
 * fragments when the keyslot enables parity p. Keyslots/directory are reserved.
 */
#define PN_BLOCK_LOG2 12
#define PN_DATA (1U << PN_BLOCK_LOG2)
#define PN_RANDOM 10
#define PN_FRAGMENT 6
#define PN_PLAIN (8 + PN_DATA)
#define PN_DATA_FRAGMENTS 687
#define PN_LANES 3
#define PN_LANE_DATA (PN_DATA_FRAGMENTS / PN_LANES)
#define PN_MAX_PARITY 16
#define PN_MAX_GROUP (PN_DATA_FRAGMENTS + PN_LANES * PN_MAX_PARITY)
#define PN_KEYSLOTS 4
#define PN_KEYSLOT_SECTORS 14
#define PN_KEYSLOT_PLAIN 64
#define PN_KEYSLOT_VERSION 5
#define PN_KEYSLOT_AREA (PN_KEYSLOTS * 2 * PN_KEYSLOT_SECTORS)
#define PN_DIRECTORY_GROUPS 2
#define PN_FLAG_AB 1U
#if PIV_AES_KEY_API
struct pn_lrw { struct aes_enckey tweak; struct aes_key prp; };
#else
struct pn_lrw { struct crypto_aes_ctx tweak, prp; };
#endif
struct piv_native {
 /* hmac/chacha are rekeyed per call (HKDF, keyslots): setup and keyslot
  * changes only, when no view request runs. rec_hmac/rec_chacha hold the
  * record MAC/stream keys, keyed once in pn_keys and then shared by
  * concurrent requests (a transform must not be rekeyed while in use).
  */
 struct crypto_shash *hmac, *rec_hmac;
 struct crypto_skcipher *chacha, *rec_chacha;
 /* record outer keys, keyslot outer keys from the directory */
 struct pn_lrw rec, ks_lrw[PN_KEYSLOTS];
 u8 ks_outer[PN_KEYSLOTS][64];
 bool ks_present[PN_KEYSLOTS];
 u64 dir_generation;
 int dir_slot;
 /* key: master key; context: record context (base || "/layout/" || ab ||
  * block_log2 || parity); base: the v5 base context used for keyslots.
  */
 u8 key[32], context[128], base[128], mac_key[32], enc_key[32];
 u32 context_length, base_length;
 /* group: sectors per record (687 + 3 * parity) */
 u32 group, parity;
 u64 hidden_bytes, records;
 bool ready, failed, ab;
 unsigned int views;
};
static struct workqueue_struct *pn_wq;

#include "piv-rs.inc"

static int pn_hash(struct crypto_shash *tfm, const void *data, size_t len, u8 out[32])
{
	struct shash_desc *d = kmalloc(sizeof(*d) + crypto_shash_descsize(tfm), GFP_NOIO);
	int r;
	if (!d) return -ENOMEM;
	d->tfm = tfm;
	r = crypto_shash_digest(d, data, len, out);
	kfree_sensitive(d);
	return r;
}

/* HKDF-SHA256 with an arbitrary-length salt (v5 key schedule). */
static int pn_hkdf(struct piv_native *n, const u8 ikm[32], const u8 *salt, size_t salt_length,
		   const char *label, u8 out[32])
{
	u8 prk[32], info[48];
	size_t length = strlen(label);
	int r;
	if (length + 13 > sizeof(info)) return -EINVAL;
	memcpy(info, "pivstore/v5/", 12); memcpy(info + 12, label, length); info[12 + length] = 1;
	r = crypto_shash_setkey(n->hmac, salt, salt_length);
	if (!r) r = pn_hash(n->hmac, ikm, 32, prk);
	if (!r) r = crypto_shash_setkey(n->hmac, prk, 32);
	if (!r) r = pn_hash(n->hmac, info, 13 + length, out);
	memzero_explicit(prk, sizeof(prk));
	return r;
}

/* LRW-AES tweakable PRP over 16-byte IVs with tweak = primary sector. */
static void pn_mask(const struct pn_lrw *k, u64 sector, u8 mask[16])
{
	u8 tweak[16] = {};
	put_unaligned_le64(sector, tweak);
	aes_encrypt(&k->tweak, mask, tweak);
}

static void pn_encode(const struct pn_lrw *k, u64 sector, const u8 value[16], u8 iv[16])
{
	u8 mask[16], block[16];
	pn_mask(k, sector, mask);
	crypto_xor_cpy(block, value, mask, 16);
	aes_encrypt(&k->prp, iv, block);
	crypto_xor(iv, mask, 16);
	memzero_explicit(block, sizeof(block));
}

static void pn_decode(const struct pn_lrw *k, u64 sector, const u8 iv[16], u8 value[16])
{
	u8 mask[16], block[16];
	pn_mask(k, sector, mask);
	crypto_xor_cpy(block, iv, mask, 16);
	aes_decrypt(&k->prp, value, block);
	crypto_xor(value, mask, 16);
	memzero_explicit(block, sizeof(block));
}

static int pn_lrw_init(struct pn_lrw *k, const u8 tweak[32], const u8 prp[32])
{
#if PIV_AES_KEY_API
	int r = aes_prepareenckey(&k->tweak, tweak, 32);
	return r ? r : aes_preparekey(&k->prp, prp, 32);
#else
	int r = aes_expandkey(&k->tweak, tweak, 32);
	return r ? r : aes_expandkey(&k->prp, prp, 32);
#endif
}

/* tag = HMAC-SHA256(mac, context || label(8|9) || LE64(id) || plain)[0:16].
 * The record key (n->mac_key) uses the pre-keyed n->rec_hmac.
 */
static int pn_tag(struct piv_native *n, const u8 mac[32], const u8 *context, size_t context_length,
		  const char *label, u64 id, const u8 *plain, size_t plain_length, u8 tag[16])
{
	size_t label_length = strlen(label), length = context_length + label_length + 8 + plain_length;
	struct crypto_shash *tfm = mac == n->mac_key ? n->rec_hmac : n->hmac;
	u8 *buffer = kmalloc(length, GFP_NOIO), digest[32];
	int r;
	if (!buffer) return -ENOMEM;
	memcpy(buffer, context, context_length);
	memcpy(buffer + context_length, label, label_length);
	put_unaligned_le64(id, buffer + context_length + label_length);
	memcpy(buffer + context_length + label_length + 8, plain, plain_length);
	r = tfm == n->hmac ? crypto_shash_setkey(tfm, mac, 32) : 0;
	if (!r) r = pn_hash(tfm, buffer, length, digest);
	if (!r) memcpy(tag, digest, 16);
	memzero_explicit(digest, sizeof(digest));
	kfree_sensitive(buffer);
	return r;
}

/* ChaCha20(enc, counter 0, nonce = tag[0:12]) keystream XOR over @buffer.
 * The record key (n->enc_key) uses the pre-keyed n->rec_chacha.
 * Callers may pass stack memory, which a
 * scatterlist must never reference (VMAP_STACK: virt_to_page() of a vmalloc
 * address names the wrong page; CONFIG_DEBUG_SG BUG()s). Bounce through the
 * linear heap. Found by the KASAN/DEBUG_SG sanitizer guest (2026-10-21).
 */
static int pn_stream(struct piv_native *n, const u8 enc[32], const u8 tag[16], u8 *buffer, size_t length)
{
	struct skcipher_request *req;
	struct scatterlist sg;
	DECLARE_CRYPTO_WAIT(wait);
	struct crypto_skcipher *tfm = enc == n->enc_key ? n->rec_chacha : n->chacha;
	u8 iv[16] = {}, *bounce;
	int r = tfm == n->chacha ? crypto_skcipher_setkey(tfm, enc, 32) : 0;
	if (r) return r;
	bounce = kmemdup(buffer, length, GFP_NOIO);
	req = skcipher_request_alloc(tfm, GFP_NOIO);
	if (!bounce || !req) { r = -ENOMEM; goto out; }
	memcpy(iv + 4, tag, 12);
	sg_init_one(&sg, bounce, length);
	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, &wait);
	skcipher_request_set_crypt(req, &sg, &sg, length, iv);
	r = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
	if (!r) memcpy(buffer, bounce, length);
out:
	skcipher_request_free(req);
	kfree_sensitive(bounce);
	return r;
}

/* The 6-byte payload suffixes of @count LRW-decoded IVs starting at @first. */
static void pn_fragments(const struct pn_lrw *k, u64 first, u32 count, const u8 *ivs, u8 *payload)
{
	u8 value[16];
	u32 j;
	for (j = 0; j < count; j++) {
		pn_decode(k, first + j, ivs + j * 16, value);
		memcpy(payload + j * PN_FRAGMENT, value + PN_RANDOM, PN_FRAGMENT);
	}
	memzero_explicit(value, sizeof(value));
}

/* SIV open of payload = tag || ChaCha20(plain) || zero padding (@bytes long).
 * PN_UNAVAILABLE if padding or tag do not verify.
 */
static int pn_payload_open(struct piv_native *n, const u8 mac[32], const u8 enc[32], const u8 *context,
			   size_t context_length, const char *label, u64 id, const u8 *payload, size_t bytes,
			   u8 *plain, size_t plain_length)
{
	u8 tag[16];
	int r = memchr_inv(payload + 16 + plain_length, 0, bytes - 16 - plain_length) ? PN_UNAVAILABLE : 0;
	if (!r) {
		memcpy(plain, payload + 16, plain_length);
		r = pn_stream(n, enc, payload, plain, plain_length);
	}
	if (!r) r = pn_tag(n, mac, context, context_length, label, id, plain, plain_length, tag);
	if (!r && crypto_memneq(tag, payload, 16)) r = PN_UNAVAILABLE;
	if (r) memzero_explicit(plain, plain_length);
	return r;
}

/* SIV over fragments (keyslots): the payload is carried as the 6-byte
 * suffixes of @count LRW-decoded IVs starting at @first.
 */
static int pn_siv_open(struct piv_native *n, const struct pn_lrw *k, const u8 mac[32], const u8 enc[32],
		       const u8 *context, size_t context_length, const char *label, u64 id,
		       u64 first, u32 count, const u8 *ivs, u8 *plain, size_t plain_length)
{
	size_t bytes = count * PN_FRAGMENT;
	u8 *payload = kmalloc(bytes, GFP_NOIO);
	int r;
	if (!payload) return -ENOMEM;
	pn_fragments(k, first, count, ivs, payload);
	r = pn_payload_open(n, mac, enc, context, context_length, label, id, payload, bytes, plain, plain_length);
	kfree_sensitive(payload);
	return r;
}

/* Fresh fragments for @plain: @ivs receives @count new IVs from @first. The
 * payload is tag || ct || zero padding up to @data_fragments fragments, then
 * (with @parity) the 3p RS parity fragments.
 */
static int pn_siv_seal(struct piv_native *n, const struct pn_lrw *k, const u8 mac[32], const u8 enc[32],
		       const u8 *context, size_t context_length, const char *label, u64 id,
		       u64 first, u32 count, u32 data_fragments, u32 parity, const u8 *plain,
		       size_t plain_length, u8 *ivs)
{
	size_t bytes = count * PN_FRAGMENT;
	u8 *payload = kzalloc(bytes, GFP_NOIO), value[16];
	u32 j;
	int r;
	if (!payload) return -ENOMEM;
	r = pn_tag(n, mac, context, context_length, label, id, plain, plain_length, payload);
	if (!r) {
		memcpy(payload + 16, plain, plain_length);
		r = pn_stream(n, enc, payload, payload + 16, plain_length);
	}
	if (!r && parity) pn_rs_parity(payload, parity, payload + data_fragments * PN_FRAGMENT);
	for (j = 0; !r && j < count; j++) {
		get_random_bytes(value, PN_RANDOM);
		memcpy(value + PN_RANDOM, payload + j * PN_FRAGMENT, PN_FRAGMENT);
		pn_encode(k, first + j, value, ivs + j * 16);
	}
	memzero_explicit(value, sizeof(value));
	kfree_sensitive(payload);
	return r;
}

/* Groups of n->group sectors follow the 112 keyslot sectors; groups 0-1 are
 * the directory. Block i uses group 2+i, or groups 2+2i/3+2i (slots A/B) with A/B.
 */
static u64 pn_group_first(struct piv_native *n, u64 group) { return PN_KEYSLOT_AREA + group * n->group; }
static u64 pn_group(struct piv_native *n, u64 index, u32 slot)
{
	return PN_DIRECTORY_GROUPS + (n->ab ? 2 * index + slot : index);
}
/* First sector after the last record group; [PN_KEYSLOT_AREA, end) carries
 * directory and record fragments under the master-key outer keys.
 */
static u64 pn_area_end(struct piv_native *n)
{
	return pn_group_first(n, PN_DIRECTORY_GROUPS + (n->ab ? 2 * n->records : n->records));
}

/* Open one record group from its n->group IVs. Fast path: SIV over the data
 * fragments. With parity, a failing tag triggers RS errors-and-erasures
 * decoding (@erased: carrier offsets that failed authentication or could not
 * be read) and a second SIV check; only a valid tag accepts.
 */
static int pn_unpack(struct piv_native *n, u64 group, const u8 *ivs, const unsigned long *erased,
		     u8 *data, u64 *generation)
{
	size_t bytes = PN_DATA_FRAGMENTS * PN_FRAGMENT;
	u8 *plain = kmalloc(PN_PLAIN, GFP_NOIO), *fragments = kmalloc(n->group * PN_FRAGMENT, GFP_NOIO);
	int r = -ENOMEM;
	if (!plain || !fragments) goto out;
	pn_fragments(&n->rec, pn_group_first(n, group), n->group, ivs, fragments);
	r = pn_payload_open(n, n->mac_key, n->enc_key, n->context, n->context_length, "/record/", group,
			    fragments, bytes, plain, PN_PLAIN);
	if (r == PN_UNAVAILABLE && n->parity) {
		r = pn_rs_correct(fragments, n->parity, erased) ? PN_UNAVAILABLE : 0;
		if (!r) r = pn_payload_open(n, n->mac_key, n->enc_key, n->context, n->context_length, "/record/",
					    group, fragments, bytes, plain, PN_PLAIN);
	}
	if (!r) memcpy(data, plain + 8, PN_DATA);
	if (!r && generation) *generation = get_unaligned_le64(plain);
out:
	kfree_sensitive(plain);
	kfree_sensitive(fragments);
	return r;
}

static int pn_pack(struct piv_native *n, u64 group, u64 generation, const u8 *data, u8 *ivs)
{
	u8 *plain = kmalloc(PN_PLAIN, GFP_NOIO);
	int r;
	if (!plain) return -ENOMEM;
	put_unaligned_le64(generation, plain);
	memcpy(plain + 8, data, PN_DATA);
	r = pn_siv_seal(n, &n->rec, n->mac_key, n->enc_key, n->context, n->context_length, "/record/",
			group, pn_group_first(n, group), n->group, PN_DATA_FRAGMENTS, n->parity, plain,
			PN_PLAIN, ivs);
	kfree_sensitive(plain);
	return r;
}

/* Keyslot keys from a KEK (salt = base context, without the layout suffix). */
struct pn_ks_keys { struct pn_lrw lrw; u8 tweak[32], prp[32], mac[32], enc[32]; };
static int pn_ks_derive(struct piv_native *n, const u8 kek[32], struct pn_ks_keys *k)
{
	int r = pn_hkdf(n, kek, n->base, n->base_length, "keyslot-tweak", k->tweak);
	if (!r) r = pn_hkdf(n, kek, n->base, n->base_length, "keyslot-prp", k->prp);
	if (!r) r = pn_hkdf(n, kek, n->base, n->base_length, "keyslot-mac", k->mac);
	if (!r) r = pn_hkdf(n, kek, n->base, n->base_length, "keyslot-enc", k->enc);
	if (!r) r = pn_lrw_init(&k->lrw, k->tweak, k->prp);
	return r;
}
static u64 pn_ks_first(u32 slot, u32 replica) { return (2 * slot + replica) * PN_KEYSLOT_SECTORS; }
static bool pn_parity_valid(u32 parity) { return parity == 0 || parity == 4 || parity == 8 || parity == 16; }

/* Keyslot plaintext: LE32 version 5 || LE32 flags || MK[32] || block_log2 ||
 * rs_parity || zero[22]. Other versions, unknown flags, a block size other
 * than 4096, unsupported parity or non-zero reserved bytes are rejected.
 */
static int pn_ks_open(struct piv_native *n, const struct pn_ks_keys *k, u32 slot, u32 replica,
		      const u8 *ivs, u32 *flags, u32 *parity, u8 master[32])
{
	u8 plain[PN_KEYSLOT_PLAIN];
	int r = pn_siv_open(n, &k->lrw, k->mac, k->enc, n->base, n->base_length, "/keyslot/",
			    2 * slot + replica, pn_ks_first(slot, replica), PN_KEYSLOT_SECTORS, ivs,
			    plain, sizeof(plain));
	if (!r && (get_unaligned_le32(plain) != PN_KEYSLOT_VERSION || (get_unaligned_le32(plain + 4) & ~PN_FLAG_AB) ||
		   plain[40] != PN_BLOCK_LOG2 || !pn_parity_valid(plain[41]) || memchr_inv(plain + 42, 0, 22)))
		r = PN_UNAVAILABLE;
	if (!r) { *flags = get_unaligned_le32(plain + 4); *parity = plain[41]; memcpy(master, plain + 8, 32); }
	memzero_explicit(plain, sizeof(plain));
	return r;
}

static int pn_ks_seal(struct piv_native *n, const struct pn_ks_keys *k, u32 slot, u32 replica, u8 *ivs)
{
	u8 plain[PN_KEYSLOT_PLAIN] = {};
	int r;
	put_unaligned_le32(PN_KEYSLOT_VERSION, plain);
	put_unaligned_le32(n->ab ? PN_FLAG_AB : 0, plain + 4);
	memcpy(plain + 8, n->key, 32);
	plain[40] = PN_BLOCK_LOG2;
	plain[41] = n->parity;
	r = pn_siv_seal(n, &k->lrw, k->mac, k->enc, n->base, n->base_length, "/keyslot/",
			2 * slot + replica, pn_ks_first(slot, replica), PN_KEYSLOT_SECTORS, PN_KEYSLOT_SECTORS,
			0, plain, sizeof(plain), ivs);
	memzero_explicit(plain, sizeof(plain));
	return r;
}

/* Directory data: per keyslot j, present byte || outer tweak key || outer prp key. */
static void pn_dir_build(struct piv_native *n, u8 *data)
{
	u32 j;
	memset(data, 0, PN_DATA);
	for (j = 0; j < PN_KEYSLOTS; j++) if (n->ks_present[j]) {
		data[j * 65] = 1;
		memcpy(data + j * 65 + 1, n->ks_outer[j], 64);
	}
}

static int pn_dir_parse(struct piv_native *n, const u8 *data)
{
	u32 j;
	if (memchr_inv(data + PN_KEYSLOTS * 65, 0, PN_DATA - PN_KEYSLOTS * 65)) return -EUCLEAN;
	for (j = 0; j < PN_KEYSLOTS; j++) {
		const u8 *e = data + j * 65;
		if (e[0] > 1 || (!e[0] && memchr_inv(e + 1, 0, 64))) return -EUCLEAN;
		n->ks_present[j] = e[0];
		memcpy(n->ks_outer[j], e + 1, 64);
		if (e[0] && pn_lrw_init(&n->ks_lrw[j], e + 1, e + 33)) return -EUCLEAN;
	}
	return 0;
}

/* Decoy-write rule: keep the 6 payload bytes of the old IV, refresh the 10 random bytes. */
static void pn_refresh(const struct pn_lrw *k, u64 sector, const u8 old[16], u8 iv[16])
{
	u8 value[16];
	do {
		pn_decode(k, sector, old, value);
		get_random_bytes(value, PN_RANDOM);
		pn_encode(k, sector, value, iv);
	} while (!memcmp(iv, old, 16));
	memzero_explicit(value, sizeof(value));
}

/* New IV for a decoy-written sector: fragment refresh where a keyslot (known
 * from the directory), the directory or a record (data or parity fragment)
 * lives; otherwise random.
 */
static void pn_decoy_iv(struct piv_native *n, u64 sector, const u8 old[16], u8 iv[16])
{
	if (sector < PN_KEYSLOT_AREA) {
		u32 slot = sector / (2 * PN_KEYSLOT_SECTORS);
		if (n->ks_present[slot]) { pn_refresh(&n->ks_lrw[slot], sector, old, iv); return; }
	} else if (sector < pn_area_end(n)) {
		pn_refresh(&n->rec, sector, old, iv);
		return;
	}
	do get_random_bytes(iv, 16); while (!memcmp(iv, old, 16));
}

/* IVs of @count sectors from @index (one bounded range). With @tolerant, a
 * sector failing primary authentication contributes its raw stored IV. Only SIV-checked decoding
 * (keyslots, the directory, hidden reads) may use that: its tag rejects any
 * damaged, missing or mixed fragment, so nothing unauthenticated is accepted.
 * With @erased (hidden records with parity), a range read error also falls
 * back to per-sector loads; sectors failing authentication or unreadable are
 * marked there (bit @at + j) as RS erasures, unreadable ones with zero IVs,
 * and *@unreadable counts the latter.
 */
static int pn_range_ivs(struct piv_control *p, u64 index, u32 count, u8 *ivs, bool tolerant,
			unsigned long *erased, u32 at, u32 *unreadable)
{
 unsigned long scratch[BITS_TO_LONGS(PIV_READ_SECTORS)];
 u32 j, iv = p->profile.iv_size;
 int r;
 /* Tolerant: failing sectors give raw IVs; with @erased they are marked. */
 r = piv_read_range(p, index, count, NULL, ivs, tolerant ? (erased ? erased : scratch) : NULL, erased ? at : 0);
 if (!tolerant || !r || !erased || r == -ENOMEM || r == -EINVAL) return r;
 /* A read error with parity: find the unreadable sectors one by one. */
 for (j = 0; j < count; j++) {
  struct piv_sector *s = NULL;
  r = piv_load_mode(p->cc, index + j, &s, true);
  if (r && erased && r != -ENOMEM) {
   memset(ivs + j * iv, 0, iv);
   __set_bit(at + j, erased);
   (*unreadable)++;
   continue;
  }
  if (r) return r;
  memcpy(ivs + j * iv, s->original + PIV_IV_AT(p->cc), iv);
  if (s->bad && erased) __set_bit(at + j, erased);
  piv_sector_free(p->cc, s);
 }
 return 0;
}

/* Collect a record group's IVs in bounded authenticated ranges. Reads pass
 * @tolerant (and with parity @erased, see pn_range_ivs); writes do not use
 * this: piv_batch_read() authenticates every sector they rewrite.
 */
static int pn_carrier_mode(struct piv_control *p, u64 first, u32 group, u8 *carrier, bool tolerant,
			   unsigned long *erased, u32 *unreadable)
{
 u32 j = 0, iv = p->profile.iv_size;
 while (j < group) {
  u32 count = min_t(u32, group - j, PIV_READ_SECTORS);
  int r = pn_range_ivs(p, first + j, count, carrier + j * iv, tolerant, erased, j, unreadable);
  if (r) return r;
  j += count;
 }
 return 0;
}

/* Collect and open one record group for reading. Raw IVs of sectors failing
 * authentication feed SIV-checked decoding; with parity, those and unreadable
 * sectors are RS erasures. An unreadable carrier whose record still does not
 * authenticate returns -EIO (a medium error is never mere unavailability, so
 * A/B never falls back over it); otherwise PN_UNAVAILABLE.
 */
static int pn_read_group(struct piv_control *p, u64 group, u8 *carrier, u8 *data, u64 *generation)
{
 struct piv_native *n = p->native;
 unsigned long erased[BITS_TO_LONGS(PN_MAX_GROUP)] = {};
 u32 unreadable = 0;
 int r = pn_carrier_mode(p, pn_group_first(n, group), n->group, carrier, true,
			 n->parity ? erased : NULL, &unreadable);
 if (!r) r = pn_unpack(n, group, carrier, erased, data, generation);
 if (r == PN_UNAVAILABLE && unreadable) r = -EIO;
 return r;
}

/* Read block i's record(s). With A/B, *slot returns the newest valid slot (or
 * -1 if none) and *generation its generation; @carrier needs 2 * n->group * 16
 * bytes. Returns PN_UNAVAILABLE when no slot authenticates.
 */
static int pn_read_slots(struct piv_control *p, u64 index, u8 *carrier, u8 *data, int *slot, u64 *generation)
{
 struct piv_native *n = p->native;
 u32 i, slots = n->ab ? 2 : 1;
 u64 best = 0, found;
 int r, chosen = -1;
 u8 *candidate = kmalloc(PN_DATA, GFP_NOIO);
 if (!candidate) return -ENOMEM;
 for (i = 0; i < slots; i++) {
  /* Hidden decoding only needs the IVs; the record's SIV tag decides. */
  r = pn_read_group(p, pn_group(n, index, i), carrier + i * n->group * 16, candidate, &found);
  /* A primary sector failing authentication makes only this slot unavailable. */
  if (r == PN_UNAVAILABLE || r == -EBADMSG) continue;
  if (r) goto out;
  if (chosen < 0 || found > best) { chosen = i; best = found; memcpy(data, candidate, PN_DATA); }
 }
 r = chosen < 0 ? PN_UNAVAILABLE : 0;
 if (slot) *slot = chosen;
 if (generation) *generation = best;
out:
 kfree_sensitive(candidate);
 return r;
}
static int pn_read_record(struct piv_control *p, u64 index, u8 *carrier, u8 *data)
{
 return pn_read_slots(p, index, carrier, data, NULL, NULL);
}
static void pn_free(struct piv_native *n)
{
 if (!n) return;
 if (!IS_ERR_OR_NULL(n->hmac)) crypto_free_shash(n->hmac);
 if (!IS_ERR_OR_NULL(n->rec_hmac)) crypto_free_shash(n->rec_hmac);
 if (!IS_ERR_OR_NULL(n->chacha)) crypto_free_skcipher(n->chacha);
 if (!IS_ERR_OR_NULL(n->rec_chacha)) crypto_free_skcipher(n->rec_chacha);
 kfree_sensitive(n);
}

struct pn_iv_key { u8 iv[16]; u8 fresh; };
static int pn_iv_cmp(const void *a, const void *b) { return memcmp(a, b, 16); }

/* Local check only, NOT a historical nonce-uniqueness guarantee: -EEXIST if a
 * fresh IV repeats one of the @count stored IVs or another fresh one (stored
 * IVs may repeat each other). Sorting keeps a whole record at O(G log G).
 */
static int pn_collides(const u8 *olds, const u8 *fresh, u32 count)
{
 struct pn_iv_key *k = kvmalloc_array(2 * count, sizeof(*k), GFP_NOIO);
 u32 i;
 int r = 0;
 if (!k) return -ENOMEM;
 for (i = 0; i < count; i++) {
  memcpy(k[i].iv, olds + i * 16, 16); k[i].fresh = 0;
  memcpy(k[count + i].iv, fresh + i * 16, 16); k[count + i].fresh = 1;
 }
 sort(k, 2 * count, sizeof(*k), pn_iv_cmp, NULL);
 /* A run of equal IVs that contains a fresh one has it next to another. */
 for (i = 1; i < 2 * count && !r; i++)
  if ((k[i].fresh || k[i - 1].fresh) && !memcmp(k[i].iv, k[i - 1].iv, 16)) r = -EEXIST;
 kvfree_sensitive(k, 2 * count * sizeof(*k));
 return r;
}

/* Encode and write one record group (G fragments, parity included): the
 * carrier is read and authenticated once (hidden-only rewrite: primary
 * plaintext unchanged); local IV collisions re-encode before anything is
 * encrypted. Without @flush the caller flushes later (initialization).
 */
static int pn_write_group(struct piv_control *p, u64 group, u64 generation, const u8 *data, bool flush,
			  bool *mutated)
{
 struct piv_native *n = p->native;
 struct piv_batch *b = NULL;
 u8 *ivs = kvmalloc(n->group * 16, GFP_NOIO);
 u32 attempt;
 int r = -ENOMEM;
 if (!ivs) return r;
 r = piv_batch_read(p, pn_group_first(n, group), n->group, 0, 0, &b);
 for (attempt = 0; !r && attempt < 16; attempt++) {
  r = pn_pack(n, group, generation, data, ivs);
  if (!r) r = pn_collides(b->olds, ivs, n->group);
  if (r != -EEXIST) break;
  r = 0;
 }
 if (!r && attempt == 16) r = -EEXIST;
 if (!r) r = piv_batch_write(b, ivs, flush, mutated);
 piv_batch_free(b);
 kvfree_sensitive(ivs, n->group * 16);
 return r;
}

/* Write the directory into the A/B directory slot not holding the current one. */
static int pn_dir_write(struct piv_control *p, bool *mutated)
{
 struct piv_native *n = p->native;
 u8 *data = kmalloc(PN_DATA, GFP_NOIO);
 int slot = n->dir_slot < 0 ? 0 : !n->dir_slot, r;
 if (!data) return -ENOMEM;
 if (n->dir_generation == U64_MAX) { kfree(data); return -EOVERFLOW; }
 pn_dir_build(n, data);
 r = pn_write_group(p, slot, n->dir_generation + 1, data, true, mutated);
 if (!r) { n->dir_slot = slot; n->dir_generation++; }
 kfree_sensitive(data);
 return r;
}

/* Write keyslot @slot (both replicas) under @kek, or overwrite it with fresh
 * random IVs when @kek is NULL.
 */
static int pn_ks_write(struct piv_control *p, u32 slot, const u8 *kek, struct pn_ks_keys *keys, bool *mutated)
{
 u8 *ivs = kmalloc(PN_KEYSLOT_SECTORS * 16, GFP_NOIO);
 u32 replica, attempt;
 int r = -ENOMEM;
 if (!ivs) return r;
 for (replica = 0; replica < 2; replica++) {
  struct piv_batch *b = NULL;
  r = piv_batch_read(p, pn_ks_first(slot, replica), PN_KEYSLOT_SECTORS, 0, 0, &b);
  for (attempt = 0; !r && attempt < 16; attempt++) {
   if (kek) r = pn_ks_seal(p->native, keys, slot, replica, ivs);
   else get_random_bytes(ivs, PN_KEYSLOT_SECTORS * 16);
   if (!r) r = pn_collides(b->olds, ivs, PN_KEYSLOT_SECTORS);
   if (r != -EEXIST) break;
   r = 0;
  }
  if (!r && attempt == 16) r = -EEXIST;
  if (!r) r = piv_batch_write(b, ivs, true, mutated);
  piv_batch_free(b);
  if (r) break;
 }
 kfree_sensitive(ivs);
 return r;
}

/* The primary sectors of block @index's record group(s): both slots with A/B
 * (adjacent groups), so one range lock covers every access to the block.
 */
static void pn_block_lock(struct piv_control *p, struct piv_range *range, u64 index, bool exclusive)
{
 struct piv_native *n = p->native;
 piv_range_lock(p, range, pn_group_first(n, pn_group(n, index, 0)), (u64)n->group * (n->ab ? 2 : 1), exclusive);
}

/* Format v5 write. A hidden write (one 4096-byte block) re-encodes its whole
 * record (with A/B, into the slot not holding the newest valid version); a
 * decoy write re-randomizes only the IVs of the primary sectors it writes,
 * preserving their fragments. Each holds an exclusive range lock over every
 * sector it reads and rewrites. Nothing is flushed here (the caller flushes
 * for FUA), except before an A/B slot rewrite. @initializing (setup only,
 * hidden): the caller flushes every few records, and with A/B slot 0 is
 * written with generation 1 without reading the slots (no record
 * authenticates under a new master key). *@mutated: storage may have changed
 * or a flush failed; either stops the owner.
 */
static int pn_write_blocks(struct piv_control *p, bool hidden, u64 offset, const u8 *data, u32 bytes,
			   bool initializing, bool *mutated)
{
 struct piv_native *n = p->native;
 struct piv_batch *b = NULL;
 struct piv_range range;
 u8 *ivs, *scratch;
 u64 unit = p->profile.sector_size, index, generation = 0;
 u32 count, i, attempt;
 int slot = 0, r = 0;
 if (hidden) {
  if (bytes != PN_DATA || offset % PN_DATA || offset / PN_DATA >= n->records) return -EINVAL;
  index = offset / PN_DATA;
  pn_block_lock(p, &range, index, true);
  if (n->ab && initializing) {
   generation = 1;
  } else if (n->ab) {
   size_t length = 2 * n->group * 16 + PN_DATA;
   scratch = kvmalloc(length, GFP_NOIO);
   r = scratch ? pn_read_slots(p, index, scratch, scratch + 2 * n->group * 16, &slot, &generation) : -ENOMEM;
   if (scratch) kvfree_sensitive(scratch, length);
   if (r == PN_UNAVAILABLE || !r) {
    slot = (r || slot < 0) ? 0 : !slot;
    generation = r ? 1 : generation + 1;
    r = generation ? 0 : -EOVERFLOW;
   }
   /* A/B keeps the newest version readable across a crash only if it is
    * durable before the other slot is overwritten. Without a completion
    * flush, an earlier write of this block (finished: the range lock
    * serializes them) may still sit in the uncommitted journal, so flush
    * first. A flush failure stops the owner like any flush error.
    */
   if (!r) {
    r = blkdev_issue_flush(p->cc->dev->bdev);
    if (r) *mutated = true;
   }
  }
  if (!r) r = pn_write_group(p, pn_group(n, index, slot), generation, data, false, mutated);
  piv_range_unlock(p, &range);
  return r;
 }
 if (initializing) return -EINVAL;
 index = offset / unit;
 count = (offset + bytes - 1) / unit - index + 1;
 if (count > PN_DECOY_ENTRIES) return -E2BIG;
 ivs = kmalloc(count * 16, GFP_NOIO);
 if (!ivs) return -ENOMEM;
 piv_range_lock(p, &range, index, count, true);
 /* A sector failing authentication (e.g. media damage) may be replaced only
  * by a write covering all of it. Its raw stored fragment is refreshed like
  * any other: the record's SIV tag decides whether it is still valid, so
  * damage stays damage and is never made authentic.
  */
 r = piv_batch_read(p, index, count, offset, bytes, &b);
 if (r) goto done;
 for (attempt = 0; attempt < 16; attempt++) {
  for (i = 0; i < count; i++)
   pn_decoy_iv(n, index + i, b->olds + i * 16, ivs + i * 16);
  r = pn_collides(b->olds, ivs, count);
  if (r != -EEXIST) break;
 }
 if (r) goto done;
 piv_batch_merge(b, offset, data, bytes);
 r = piv_batch_write(b, ivs, false, mutated);
done:
 piv_range_unlock(p, &range);
 piv_batch_free(b);
 kfree_sensitive(ivs);
 return r;
}

/* noinline: kprobe-based lifecycle/profile/cancel tests attach to pn_write.
 * *mutated reports whether storage may have changed. Every failure before that
 * point leaves the disk untouched; the caller may then fail only this request.
 */
static noinline int pn_write(struct piv_control *p, bool hidden, u64 offset, const u8 *data, u32 bytes,
			     bool initializing, bool *mutated)
{
 return pn_write_blocks(p, hidden, offset, data, bytes, initializing, mutated);
}

/* Cooperative setup only: never interrupt an in-flight hidden-record write.
 * Completed initialization records remain committed; cancellation is not undo.
 */
static int pn_setup_poll(void)
{
 cond_resched();
 return signal_pending(current) ? -EINTR : 0;
}

/* v5 record keys from the master key and the layout (n->ab, n->parity):
 * context = base || "/layout/" || ab || block_log2 || rs_parity, so a volume
 * opened with other parameters fails the SIV check. Geometry: G = 687 + 3p,
 * blocks = floor((N - 112) / G) - 2, halved with A/B.
 */
static int pn_keys(struct piv_native *n, u64 sectors)
{
 u8 tweak[32], prp[32];
 u64 groups;
 int r;
 if (!pn_parity_valid(n->parity) || n->base_length + 11 > sizeof(n->context)) return -EINVAL;
 memcpy(n->context, n->base, n->base_length);
 memcpy(n->context + n->base_length, "/layout/", 8);
 n->context[n->base_length + 8] = n->ab;
 n->context[n->base_length + 9] = PN_BLOCK_LOG2;
 n->context[n->base_length + 10] = n->parity;
 n->context_length = n->base_length + 11;
 n->group = PN_DATA_FRAGMENTS + PN_LANES * n->parity;
 groups = sectors > PN_KEYSLOT_AREA ? (sectors - PN_KEYSLOT_AREA) / n->group : 0;
 n->records = groups > PN_DIRECTORY_GROUPS ? groups - PN_DIRECTORY_GROUPS : 0;
 if (n->ab) n->records /= 2;
 if (!n->records) return -EINVAL;
 n->hidden_bytes = n->records * PN_DATA;
 r = pn_hkdf(n, n->key, n->context, n->context_length, "tweak", tweak);
 if (!r) r = pn_hkdf(n, n->key, n->context, n->context_length, "prp", prp);
 if (!r) r = pn_lrw_init(&n->rec, tweak, prp);
 if (!r) r = pn_hkdf(n, n->key, n->context, n->context_length, "mac", n->mac_key);
 if (!r) r = pn_hkdf(n, n->key, n->context, n->context_length, "enc", n->enc_key);
 if (!r) r = crypto_shash_setkey(n->rec_hmac, n->mac_key, 32);
 if (!r) r = crypto_skcipher_setkey(n->rec_chacha, n->enc_key, 32);
 memzero_explicit(tweak, sizeof(tweak)); memzero_explicit(prp, sizeof(prp));
 return r;
}

/* Fast key check: try every keyslot replica under the KEK. 0 on success with
 * n->key = master key and n->ab/n->parity set; PN_UNAVAILABLE if none
 * authenticates.
 */
static int pn_unlock(struct piv_native *n, const u8 kek[32], const u8 *ks_ivs)
{
 struct pn_ks_keys *k = kzalloc(sizeof(*k), GFP_NOIO);
 u32 slot, replica, flags = 0, parity = 0;
 u8 master[32];
 int r;
 if (!k) return -ENOMEM;
 r = pn_ks_derive(n, kek, k);
   for (slot = 0; !r && slot < PN_KEYSLOTS; slot++)
  for (replica = 0; replica < 2; replica++) {
   r = pn_ks_open(n, k, slot, replica, ks_ivs + pn_ks_first(slot, replica) * 16, &flags, &parity, master);
   if (r != PN_UNAVAILABLE) goto out;
   r = 0;
  }
 r = r ? r : PN_UNAVAILABLE;
out:
 if (!r) { memcpy(n->key, master, 32); n->ab = flags & PN_FLAG_AB; n->parity = parity; }
 memzero_explicit(master, sizeof(master));
 kfree_sensitive(k);
 return r;
}

/* Read the directory (newest valid of groups 0/1, ordinary G-sector records
 * with the volume's parity) and load keyslot outer keys.
 */
static int pn_dir_load(struct piv_control *p)
{
 struct piv_native *n = p->native;
 size_t length = n->group * 16 + PN_DATA;
 u8 *carrier = kvmalloc(length, GFP_NOIO);
 u64 generation;
 int r, slot;
 n->dir_slot = -1;
 if (!carrier) return -ENOMEM;
 for (slot = 0; slot < 2; slot++) {
  r = pn_read_group(p, slot, carrier, carrier + n->group * 16, &generation);
  if (r == PN_UNAVAILABLE || r == -EBADMSG) continue;
  if (r) goto out;
  if (n->dir_slot < 0 || generation > n->dir_generation) {
   r = pn_dir_parse(n, carrier + n->group * 16);
   if (r) goto out;
   n->dir_slot = slot; n->dir_generation = generation;
  }
 }
 /* Without a directory, decoy writes would destroy other keyslots: refuse. */
 r = n->dir_slot < 0 ? -EUCLEAN : 0;
out:
 kvfree_sensitive(carrier, length);
 return r;
}

/* Fast key check once the scan has collected every keyslot IV (no extra I/O),
 * then the record keys and the directory: decoy writes must refresh every
 * keyslot it lists, so setup refuses without it.
 */
static int pn_setup_unlock(struct piv_control *p, struct piv_native *n, const u8 key[32], const u8 *ks_ivs)
{
 int r = pn_unlock(n, key, ks_ivs);
 if (r == PN_UNAVAILABLE) return -EKEYREJECTED;
 if (!r) r = pn_keys(n, p->profile.sectors);
 if (!r) r = pn_dir_load(p);
 return r;
}

/* Fill outcome of one block (PIV_SETUP_FILL). */
enum { PN_FILL_VALID, PN_FILL_WRITTEN, PN_FILL_FAILED };

/* Local, pre-mutation failures that leave one block as it was during a fill:
 * a carrier sector failing authentication or unreadable. Anything else
 * (allocation, nonce exhaustion, encryption cap) aborts the whole setup.
 */
static bool pn_fill_local(int r) { return r == -EBADMSG || r == -EIO || r == -ENODATA || r == -EILSEQ; }

/* Fill one block: skip it if a record (any A/B slot; with parity, possibly
 * after RS correction) authenticates under the master key, else write a zero
 * record exactly as initialization does (A/B: slot 0, generation 1). The
 * write is the ordinary strict rewrite: every carrier sector must authenticate
 * before anything is written, so a damaged or unreadable carrier stays as it
 * was and counts as failed. Setup holds p->lock and no views exist, so
 * nothing changes the block between the check and the write.
 */
static int pn_fill_block(struct piv_control *p, u64 index, const u8 *zero, int *outcome)
{
 struct piv_native *n = p->native;
 struct piv_range range;
 size_t length = 2 * n->group * 16 + PN_DATA;
 u8 *scratch = kvmalloc(length, GFP_NOIO);
 bool mutated = false;
 int r;
 if (!scratch) return -ENOMEM;
 pn_block_lock(p, &range, index, false);
 r = pn_read_slots(p, index, scratch, scratch + 2 * n->group * 16, NULL, NULL);
 piv_range_unlock(p, &range);
 kvfree_sensitive(scratch, length);
 if (!r) { *outcome = PN_FILL_VALID; return 0; }
 /* A medium error is never mere unavailability: the strict write would read
  * the same carrier, so leave the block alone.
  */
 if (pn_fill_local(r)) { *outcome = PN_FILL_FAILED; return 0; }
 if (r != PN_UNAVAILABLE) return r;
 r = pn_write(p, true, index * PN_DATA, zero, PN_DATA, true, &mutated);
 if (!r) *outcome = PN_FILL_WRITTEN;
 else if (!mutated && pn_fill_local(r) && !READ_ONCE(p->failed)) { *outcome = PN_FILL_FAILED; r = 0; }
 return r;
}

/* One initialization record (or fill block) per work item (setup holds
 * p->lock; no views exist, so nothing else touches the owner meanwhile).
 */
struct pn_init_work {
 struct work_struct work;
 struct piv_control *p;
 const u8 *zero;
 u64 index;
 int result, outcome;
 bool fill;
 atomic_t *pending;
 struct completion *done;
};

static void pn_init_worker(struct work_struct *work)
{
 struct pn_init_work *w = container_of(work, struct pn_init_work, work);
 unsigned int noio = memalloc_noio_save();
 bool mutated = false;
 if (w->fill)
  w->result = pn_fill_block(w->p, w->index, w->zero, &w->outcome);
 else
  w->result = pn_write(w->p, true, w->index * PN_DATA, w->zero, PN_DATA, true, &mutated);
 memalloc_noio_restore(noio);
 if (atomic_dec_and_test(w->pending)) complete(w->done);
}

/* Write zero records (or, with @counts, fill blocks) [@first, @first +
 * @count) concurrently and wait for all of them; returns the first failure.
 * @counts accumulates per-outcome block counts (valid, written, failed).
 */
static int pn_init_round(struct piv_control *p, const u8 *zero, u64 first, u32 count, u64 *counts)
{
 struct pn_init_work *w = kcalloc(count, sizeof(*w), GFP_NOIO);
 struct completion done;
 atomic_t pending;
 u32 i;
 int r = 0;
 if (!w) return -ENOMEM;
 init_completion(&done);
 atomic_set(&pending, count + 1);
 for (i = 0; i < count; i++) {
  INIT_WORK(&w[i].work, pn_init_worker);
  w[i].p = p; w[i].zero = zero; w[i].index = first + i; w[i].fill = counts;
  w[i].pending = &pending; w[i].done = &done;
  queue_work(pn_wq, &w[i].work);
 }
 if (!atomic_dec_and_test(&pending)) wait_for_completion_io(&done);
 for (i = 0; i < count && !r; i++) r = w[i].result;
 for (i = 0; !r && counts && i < count; i++) counts[w[i].outcome]++;
 kfree(w);
 return r;
}

/* Initialization records (@counts NULL) or a fill, in rounds of
 * PN_INIT_PARALLEL concurrent blocks; cancellation is polled between rounds,
 * when every record written so far is complete. Initialization flushes every
 * PN_INIT_FLUSH_RECORDS records; a fill flushes at the same points if it
 * wrote anything since the last flush. Completed records stay committed, also
 * when cancelled: they are flushed before returning. A failed record write
 * already failed the attempt.
 */
static int pn_records(struct piv_control *p, u64 *counts)
{
 struct piv_native *n = p->native;
 u8 *zero = kzalloc(PN_DATA, GFP_NOIO);
 u64 i, flushed = 0;
 int r = 0;
 if (!zero) return -ENOMEM;
 for (i = 0; i < n->records;) {
  u32 count = min_t(u64, n->records - i, PN_INIT_PARALLEL);
  r = pn_setup_poll(); if (r) break;
  r = pn_init_round(p, zero, i, count, counts); if (r) break;
  /* A concurrent work item's failed write stopped the owner. */
  if (READ_ONCE(p->failed)) { r = -EIO; break; }
  i += count;
  if (i % PN_INIT_FLUSH_RECORDS == 0 && (!counts || counts[PN_FILL_WRITTEN] != flushed)) {
   r = blkdev_issue_flush(p->cc->dev->bdev); if (r) break;
   if (counts) flushed = counts[PN_FILL_WRITTEN];
  }
 }
 if ((!r || r == -EINTR) && (!counts || counts[PN_FILL_WRITTEN] != flushed)) {
  int f = blkdev_issue_flush(p->cc->dev->bdev);
  if (f) r = f;
 }
 kfree_sensitive(zero);
 return r;
}

static int pn_setup(struct piv_control *p, struct file *controller, struct piv_native_setup *s)
{
 struct piv_native *n;
 u8 *ivs = NULL, *ks_ivs = NULL;
 u64 i;
 u32 j;
 bool initialize = s->flags & PIV_SETUP_INITIALIZE, ab = s->flags & PIV_SETUP_AB, mutated, ks_done = false;
 bool verify = s->flags & PIV_SETUP_VERIFY, quick = s->flags & PIV_SETUP_QUICK, fill = s->flags & PIV_SETUP_FILL;
 u64 scan_end, minimum;
 int r;
 if (s->version != 6 || s->size != sizeof(*s) || s->generation != p->profile.generation ||
     s->context_length > 112 || s->context_length <= 19 ||
     memcmp(s->context, "pivstore/volume/v5", 19) ||
     (s->flags & ~(PIV_SETUP_INITIALIZE | PIV_SETUP_AB | PIV_SETUP_VERIFY | PIV_SETUP_QUICK | PIV_SETUP_FILL)) ||
     !pn_parity_valid(s->parity) || s->reserved || s->valid || s->written || s->failed) return -EINVAL;
 /* Format v5 needs 16-byte IVs. A/B and parity are chosen at initialization
  * and afterwards read from the keyslot. QUICK only initializes; FILL needs an
  * existing master key (it is the separate, explicit completion step).
  */
 if (p->profile.iv_size != 16 || ((ab || s->parity || quick) && !initialize) || (fill && initialize)) return -EINVAL;
 if (p->native || !piv_quiesced(p) || !p->transaction || p->controller != controller || READ_ONCE(p->failed)) return -EBUSY;
 /* Bound every primary byte offset by the kernel's signed file limit.
  * Fragment indices, hidden capacity and 512-byte addresses are then smaller;
  * all per-request allocations remain bounded independently of volume size.
  * Minimum: keyslots, the directory and one block (112 + 3G, A/B 112 + 4G);
  * without initialize the keyslot's parity may raise G (pn_keys rechecks).
  */
 minimum = PN_KEYSLOT_AREA + (PN_DIRECTORY_GROUPS + (ab ? 2 : 1)) * (PN_DATA_FRAGMENTS + PN_LANES * s->parity);
 if (p->profile.sectors < minimum ||
     p->profile.sectors > (u64)MAX_LFS_FILESIZE / p->profile.sector_size) return -EINVAL;
 n = kzalloc(sizeof(*n), GFP_NOIO); if (!n) return -ENOMEM;
 memcpy(n->key, s->key, 32);
 memcpy(n->base, s->context, s->context_length);
 n->base_length = s->context_length;
 n->dir_slot = -1;
 n->hmac = crypto_alloc_shash("hmac(sha256)", 0, 0);
 n->rec_hmac = crypto_alloc_shash("hmac(sha256)", 0, 0);
 n->chacha = crypto_alloc_skcipher("chacha20", 0, 0);
 n->rec_chacha = crypto_alloc_skcipher("chacha20", 0, 0);
 if (IS_ERR(n->hmac) || IS_ERR(n->rec_hmac) || IS_ERR(n->chacha) || IS_ERR(n->rec_chacha)) { r = -ENOENT; goto bad; }
 p->native = n;
 /* Key guard: a keyslot must authenticate under the given KEK; its IVs come
  * from the keyslot-area scan. A decoy write under an unproven key would
  * destroy hidden data. By default (user decision 2026-10-21) setup scans only
  * the keyslot area: every later request authenticates exactly the sectors it
  * touches, so a full scan adds no protection, only O(volume) setup time.
  * PIV_SETUP_VERIFY restores the strict full audit (any failing sector
  * refuses). Without it, keyslot sectors failing authentication contribute
  * their raw stored IVs: replicas exist for this, and the keyslot SIV tag
  * rejects any damaged fragment, so nothing unauthenticated is accepted.
  */
 scan_end = verify ? p->profile.sectors : PN_KEYSLOT_AREA;
 ivs = kmalloc(PIV_READ_SECTORS * 16, GFP_NOIO);
 if (!initialize) ks_ivs = kzalloc(PN_KEYSLOT_AREA * 16, GFP_NOIO);
 if (!ivs || (!initialize && !ks_ivs)) { r = -ENOMEM; goto bad; }
 for (i = 0; i < scan_end;) {
  u32 count = min_t(u64, scan_end - i, PIV_READ_SECTORS);
  r = pn_setup_poll(); if (r) goto bad;
  r = pn_range_ivs(p, i, count, ivs, !verify, NULL, 0, NULL); if (r) goto bad;
  for (j = 0; ks_ivs && j < count && i + j < PN_KEYSLOT_AREA; j++)
   memcpy(ks_ivs + (i + j) * 16, ivs + j * 16, 16);
  i += count;
  /* Unlock as soon as the keyslot area is collected. */
  if (ks_ivs && !ks_done && i >= PN_KEYSLOT_AREA) {
   ks_done = true;
   r = pn_setup_unlock(p, n, s->key, ks_ivs);
   if (r) goto bad;
  }
 }
 if (initialize) {
  /* New master key; keyslot 0 wraps it under the KEK and the directory lists it. */
  struct pn_ks_keys *k = kzalloc(sizeof(*k), GFP_NOIO);
  if (!k) { r = -ENOMEM; goto bad; }
  n->ab = ab;
  n->parity = s->parity;
  r = pn_ks_derive(n, s->key, k);
  get_random_bytes(n->key, 32);
  if (!r) r = pn_keys(n, p->profile.sectors);
  if (!r) {
   n->ks_present[0] = true;
   memcpy(n->ks_outer[0], k->tweak, 32); memcpy(n->ks_outer[0] + 32, k->prp, 32);
   n->ks_lrw[0] = k->lrw;
   r = pn_ks_write(p, 0, s->key, k, &mutated);
  }
  kfree_sensitive(k);
  if (!r) r = pn_dir_write(p, &mutated);
  if (r) goto bad;
  /* Quick: no records; never-written blocks stay unavailable until written or filled. */
  if (!quick) { r = pn_records(p, NULL); if (r) goto bad; }
 } else if (fill) {
  u64 counts[3] = {};
  r = pn_records(p, counts);
  if (r) goto bad;
  s->valid = counts[PN_FILL_VALID]; s->written = counts[PN_FILL_WRITTEN]; s->failed = counts[PN_FILL_FAILED];
 }
 r = pn_setup_poll(); if (r) goto bad;
 r = piv_checkpoint(p->cc); if (r) goto bad;
 r = pn_setup_poll(); if (r) goto bad;
 n->ready = true; p->transaction = false; p->controller = NULL;
 kfree_sensitive(ivs); kfree_sensitive(ks_ivs);
 return 0;
bad:
 kfree_sensitive(ivs); kfree_sensitive(ks_ivs);
 p->native = NULL; pn_free(n);
 return r;
}

/* Add or remove a v5 keyslot on an active owner (same MK and parameters). The master key stays in
 * memory; records are untouched. Add writes the keyslot, then the directory;
 * remove updates the directory, then overwrites the keyslot with random IVs.
 * The last keyslot cannot be removed. Failures after a lower write fail-stop.
 */
static int pn_keyslot(struct piv_control *p, struct piv_native_keyslot *ks)
{
 struct piv_native *n = p->native;
 struct pn_ks_keys *k;
 bool mutated = false;
 u32 j, present = 0;
 int r;
 if (ks->version != 1 || ks->size != sizeof(*ks) || ks->generation != p->profile.generation ||
     ks->slot >= PN_KEYSLOTS || (ks->op != PIV_KEYSLOT_ADD && ks->op != PIV_KEYSLOT_REMOVE) ||
     memchr_inv(ks->reserved, 0, sizeof(ks->reserved)) ||
     (ks->op == PIV_KEYSLOT_REMOVE && memchr_inv(ks->kek, 0, sizeof(ks->kek)))) return -EINVAL;
 if (!n || !n->ready || READ_ONCE(n->failed) || READ_ONCE(p->failed) || p->blocked) return -EBUSY;
 for (j = 0; j < PN_KEYSLOTS; j++) present += n->ks_present[j];
 if (ks->op == PIV_KEYSLOT_ADD) {
  if (n->ks_present[ks->slot]) return -EEXIST;
  k = kzalloc(sizeof(*k), GFP_NOIO);
  if (!k) return -ENOMEM;
  r = pn_ks_derive(n, ks->kek, k);
  if (!r) r = pn_ks_write(p, ks->slot, ks->kek, k, &mutated);
  if (!r) {
   n->ks_present[ks->slot] = true;
   memcpy(n->ks_outer[ks->slot], k->tweak, 32); memcpy(n->ks_outer[ks->slot] + 32, k->prp, 32);
   n->ks_lrw[ks->slot] = k->lrw;
   r = pn_dir_write(p, &mutated);
  }
  kfree_sensitive(k);
 } else {
  if (!n->ks_present[ks->slot]) return -ENOENT;
  if (present == 1) return -EBUSY;
  n->ks_present[ks->slot] = false;
  memzero_explicit(n->ks_outer[ks->slot], 64);
  memzero_explicit(&n->ks_lrw[ks->slot], sizeof(n->ks_lrw[ks->slot]));
  r = pn_dir_write(p, &mutated);
  if (!r) r = pn_ks_write(p, ks->slot, NULL, NULL, &mutated);
 }
 if (r && mutated) { WRITE_ONCE(p->failed, true); WRITE_ONCE(n->failed, true); }
 return r;
}

/* Hidden blocks are read under a shared range lock over their record
 * group(s), so a concurrent hidden write is never collected half-done. Decoy
 * reads need none (each sector is whole and authenticated on its own).
 */
static int pn_read(struct piv_control *p, bool hidden, u64 offset, u8 *data, u32 bytes)
{
 u64 unit = hidden ? PN_DATA : p->profile.sector_size, first = offset / unit, last = (offset + bytes - 1) / unit, i;
 size_t carrier = 2 * PN_MAX_GROUP * 16;
 size_t length = hidden ? carrier + PN_DATA : min_t(u64, last - first + 1, PIV_READ_SECTORS) * unit;
 u8 *record = kvmalloc(length, GFP_NOIO);
 int r = 0;
 if (!record) return -ENOMEM;
 for (i = first; i <= last; i++) {
  u64 start = i * unit, lo = max(start, offset), hi = min(start + unit, offset + bytes);
  if (hidden) {
   struct piv_range range;
   pn_block_lock(p, &range, i, false);
   r = pn_read_record(p, i, record, record + carrier);
   piv_range_unlock(p, &range);
   if (r) break;
   memcpy(data + lo - offset, record + carrier + lo - start, hi - lo);
  } else {
   u32 count = min_t(u64, last - i + 1, PIV_READ_SECTORS);
   r = piv_read_range(p, i, count, record, NULL, NULL, 0); if (r) break;
   hi = min(start + count * unit, offset + bytes);
   memcpy(data + lo - offset, record + lo - start, hi - lo);
   i += count - 1;
  }
 }
 kvfree_sensitive(record, length); return r;
}

struct pn_view { struct piv_control *p; struct dm_dev *owner; bool hidden; };
struct pn_work { struct work_struct work; struct piv_control *p; struct bio *bio; u64 offset; bool hidden; };

static void pn_copy_bio(struct bio *bio, u8 *buffer, bool to_bio)
{
	struct bio_vec vec;
	struct bvec_iter iter;
	u32 offset = 0;
	bio_for_each_segment(vec, bio, iter) {
		void *at = kmap_local_page(vec.bv_page);
		if (to_bio) memcpy(at + vec.bv_offset, buffer + offset, vec.bv_len);
		else memcpy(buffer + offset, at + vec.bv_offset, vec.bv_len);
		kunmap_local(at); offset += vec.bv_len;
	}
}

/* noinline: the lifecycle test traces native completions here. A probe on
 * bio_endio also fires for interrupt-context lower completions, which can nest
 * inside another probe's handler and be missed; this is process context only.
 */
static noinline void pn_endio(struct bio *bio, blk_status_t status)
{
	bio->bi_status = status;
	bio_endio(bio);
}

/* One public bio. Workers run concurrently under p->io (shared); owner state
 * changes take it exclusively and so wait for them. Every access to p->native
 * happens before the bio completes, so a view removed after its last
 * completion never races a worker.
 */
static void pn_worker(struct work_struct *work)
{
	struct pn_work *w = container_of(work, struct pn_work, work);
	struct piv_control *p = w->p;
	struct piv_native *n;
	struct bio *bio = w->bio;
	u32 bytes = bio->bi_iter.bi_size;
	u8 *buffer = NULL;
	unsigned int noio;
	bool mutated = false, flushing = false;
	int r = -EIO;
	down_read(&p->io); noio = memalloc_noio_save();
	n = p->native;
	if (!p->live || !n || !n->ready || READ_ONCE(n->failed) ||
	    p->blocked || p->transaction || READ_ONCE(p->failed)) goto done;
	if (!bytes && (bio_op(bio) == REQ_OP_FLUSH || (bio->bi_opf & REQ_PREFLUSH))) {
		/* Covers every write completed before this flush was issued. */
		flushing = true;
		r = blkdev_issue_flush(p->cc->dev->bdev);
	} else {
		u64 limit = w->hidden ? n->hidden_bytes : p->profile.sectors * p->profile.sector_size;
		/* Hidden requests are whole aligned 4096-byte blocks (DM splits per block). */
		if (!bytes || bytes > (w->hidden ? PN_DATA : PN_DECOY_BYTES) || (w->offset & 511) ||
		    (bytes & 511) || (w->hidden && (bytes != PN_DATA || w->offset % PN_DATA)) ||
		    w->offset > limit || bytes > limit - w->offset) { r = -EINVAL; goto done; }
		buffer = kvmalloc(bytes, GFP_NOIO);
		if (!buffer) { r = -ENOMEM; goto done; }
		if (bio_op(bio) == REQ_OP_READ) {
			r = pn_read(p, w->hidden, w->offset, buffer, bytes);
			if (!r) pn_copy_bio(bio, buffer, true);
		} else if (bio_op(bio) == REQ_OP_WRITE) {
			pn_copy_bio(bio, buffer, false);
			/* Drain earlier journal writes before a WRITE|PREFLUSH payload. */
			flushing = bio->bi_opf & REQ_PREFLUSH;
			r = flushing ? blkdev_issue_flush(p->cc->dev->bdev) : 0;
			if (!r) {
				flushing = false;
				r = pn_write(p, w->hidden, w->offset, buffer, bytes, false, &mutated);
			}
			/* FUA: durable before completion. Plain writes are not flushed,
			 * as in stock dm-crypt; a later flush or FUA request covers them.
			 */
			if (!r && (bio->bi_opf & REQ_FUA)) {
				flushing = true;
				r = blkdev_issue_flush(p->cc->dev->bdev);
			}
		} else r = -EOPNOTSUPP;
	}
	/* Scoped isolation: reads, validation, authentication, allocation, nonce
	 * and preparation failures change no storage and fail only this bio. A
	 * failed flush leaves earlier durability unknown, and a failure once
	 * writing began may have partially written; both still stop the shared
	 * owner.
	 */
	if (r < 0 && (mutated || flushing)) { WRITE_ONCE(p->failed, true); WRITE_ONCE(n->failed, true); }
	/* A write or flush still in flight when a concurrent request stopped the
	 * owner reports EIO: whether it reached storage is unknown.
	 */
	if (!r && bio_op(bio) != REQ_OP_READ && READ_ONCE(p->failed)) r = -EIO;
done:
	if (buffer) kvfree_sensitive(buffer, bytes);
	memalloc_noio_restore(noio); up_read(&p->io);
	pn_endio(bio, errno_to_blk_status(r > 0 ? -EIO : r));
	kref_put(&p->refs, piv_free); kfree(w);
}

static int pn_map(struct dm_target *ti, struct bio *bio)
{
	struct pn_view *v = ti->private;
	struct pn_work *w;
	u64 sector = dm_target_offset(ti, bio->bi_iter.bi_sector);
	if (sector > ((u64)MAX_LFS_FILESIZE >> 9)) return DM_MAPIO_KILL;
	if (bio_op(bio) != REQ_OP_READ && bio_op(bio) != REQ_OP_WRITE && bio_op(bio) != REQ_OP_FLUSH)
		return DM_MAPIO_KILL;
	w = kmalloc(sizeof(*w), GFP_NOWAIT | __GFP_NOWARN);
	if (!w) return DM_MAPIO_REQUEUE;
	INIT_WORK(&w->work, pn_worker); w->p = v->p; w->bio = bio; w->hidden = v->hidden;
	w->offset = sector << 9;
	kref_get(&w->p->refs); queue_work(pn_wq, &w->work);
	return DM_MAPIO_SUBMITTED;
}

static int pn_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct pn_view *v;
	struct piv_control *p, *found = NULL;
	u64 generation;
	int r;
	if (argc != 3 || kstrtou64(argv[1], 10, &generation) ||
	    (strcmp(argv[2], "hidden") && strcmp(argv[2], "decoy"))) return -EINVAL;
	v = kzalloc(sizeof(*v), GFP_KERNEL); if (!v) return -ENOMEM;
	mutex_lock(&piv_controls_lock);
	list_for_each_entry(p, &piv_controls, list) if (p->profile.generation == generation) { kref_get(&p->refs); found = p; break; }
	mutex_unlock(&piv_controls_lock);
	if (!found) { kfree(v); return -ENODEV; }
	v->p = found; v->hidden = !strcmp(argv[2], "hidden");
	r = dm_get_device(ti, argv[0], BLK_OPEN_READ | BLK_OPEN_WRITE, &v->owner);
	if (r) goto free_ref;
	mutex_lock(&found->lock);
	if (!found->live || !found->native || !found->native->ready || READ_ONCE(found->native->failed) ||
	    disk_devt(v->owner->bdev->bd_disk) != MKDEV(found->devices.owner_major, found->devices.owner_minor) ||
	    ti->begin || ti->len != (v->hidden ? found->native->hidden_bytes / 512 : found->profile.sectors * (found->profile.sector_size / 512)) ||
	    (found->native->views & (v->hidden ? 2 : 1))) r = -EINVAL;
	else { found->native->views |= v->hidden ? 2 : 1; r = 0; }
	mutex_unlock(&found->lock);
	if (r) { dm_put_device(ti, v->owner); goto free_ref; }
	ti->private = v; ti->num_flush_bios = 1;
	r = dm_set_target_max_io_len(ti, (v->hidden ? PN_DATA : PN_DECOY_BYTES) / 512);
	if (!r) return 0;
	mutex_lock(&found->lock); found->native->views &= ~(v->hidden ? 2 : 1); mutex_unlock(&found->lock);
	dm_put_device(ti, v->owner);
free_ref:
	kref_put(&found->refs, piv_free); kfree(v); return r;
}

static void pn_dtr(struct dm_target *ti)
{
	struct pn_view *v = ti->private;
	mutex_lock(&v->p->lock);
	if (v->p->native) v->p->native->views &= ~(v->hidden ? 2 : 1);
	mutex_unlock(&v->p->lock);
	dm_put_device(ti, v->owner); kref_put(&v->p->refs, piv_free); kfree(v);
}
static int pn_iterate(struct dm_target *ti, iterate_devices_callout_fn fn, void *data)
{
	struct pn_view *v = ti->private;
	return fn(ti, v->owner, 0, v->p->profile.sectors * (v->p->profile.sector_size / 512), data);
}
static void pn_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct pn_view *v = ti->private;
	/* Decoy: authenticated primary-sector RMW permits 512-byte logical
	 * requests. Hidden: one record per 4096-byte block, no RMW.
	 */
	limits->logical_block_size = v->hidden ? PN_DATA : 512;
	limits->physical_block_size = v->hidden ? PN_DATA : v->p->profile.sector_size;
	limits->io_min = limits->physical_block_size; limits->dma_alignment = 511;
}
static void pn_status(struct dm_target *ti, status_type_t type, unsigned int flags, char *result, unsigned int maxlen)
{
	struct pn_view *v = ti->private;
	unsigned int sz = 0;
	DMEMIT("%s %llu %s", v->owner->name, (unsigned long long)v->p->profile.generation, v->hidden ? "hidden" : "decoy");
}
static struct target_type piv_view_target = {
	.name = "piv-view", .version = {0, 4, 0}, .module = THIS_MODULE,
	.ctr = pn_ctr, .dtr = pn_dtr, .map = pn_map, .iterate_devices = pn_iterate,
	.io_hints = pn_hints, .status = pn_status,
};
