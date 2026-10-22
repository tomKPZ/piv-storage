/* SPDX-License-Identifier: GPL-2.0-only */
/* Stateless paired views over format v4 (docs/format-v4.md; AEGIS-128 16-byte
 * IVs only since 2026-10-21, when format v3 and the 12-byte-IV profiles were
 * removed). Only stock dm-integrity persists recovery information. Whole
 * hidden blocks authenticate, but interrupted multi-sector writes can destroy
 * them (A/B slots keep the previous version). All work is serialized under the
 * owner lock in NOIO context.
 */
/* Positive internal sentinel: LOCAL hidden unavailability. -ENODATA may also
 * mean a block medium error and is never treated as unavailability.
 */
#define PN_UNAVAILABLE 1
#define PN_DATA 512
#define PN_MAX_ENTRIES 96
/* Power-of-two DM split boundary: a decoy work item touches at most 32
 * primary sectors (16 KiB / 512), within PN_MAX_ENTRIES prepared tuples. No
 * cross-bio accumulation or delayed completion is used.
 */
#define PN_DECOY_BYTES 16384
/* Format v4 (docs/format-v4.md), 16-byte IVs only: each primary IV carries
 * LRW-AES(r[10] || d[6]) with tweak = primary sector; one 512-byte block is a
 * 536-byte SIV payload in 90 fragments. Keyslots/directory are reserved.
 */
#define PN_V4_RANDOM 10
#define PN_V4_FRAGMENT 6
#define PN_V4_PLAIN 520
#define PN_V4_PAYLOAD 536
#define PN_V4_GROUP 90
#define PN_V4_CARRIER (PN_V4_GROUP * 16)
#define PN_V4_KEYSLOTS 4
#define PN_V4_KEYSLOT_SECTORS 14
#define PN_V4_KEYSLOT_PLAIN 64
#define PN_V4_KEYSLOT_AREA (PN_V4_KEYSLOTS * 2 * PN_V4_KEYSLOT_SECTORS)
#define PN_V4_RESERVED (PN_V4_KEYSLOT_AREA + 2 * PN_V4_GROUP)
#define PN_V4_FLAG_AB 1U
#define PN_MAX_CARRIER (2 * PN_V4_CARRIER)
struct pn_entry {
 __le64 sector;
 __le32 primary;
 u8 replace; /* full-sector decoy write over a sector failing authentication */
 u8 old[16], tuple[PIV_TUPLE_BYTES];
} __packed;
#if PIV_AES_KEY_API
struct pn_lrw { struct aes_enckey tweak; struct aes_key prp; };
#else
struct pn_lrw { struct crypto_aes_ctx tweak, prp; };
#endif
struct piv_native {
 struct crypto_shash *hmac;
 /* record outer keys, keyslot outer keys from the directory */
 struct crypto_skcipher *chacha;
 struct pn_lrw rec, ks_lrw[PN_V4_KEYSLOTS];
 u8 ks_outer[PN_V4_KEYSLOTS][64];
 bool ks_present[PN_V4_KEYSLOTS];
 u64 dir_generation;
 int dir_slot;
 /* key: master key; context: record context (base, + "/ab" with A/B);
  * base: the v4 base context used for keyslots and record keys.
  */
 u8 key[32], context[128], base[128], mac_key[32], enc_key[32];
 u32 context_length, base_length;
 u64 hidden_bytes, records;
 bool ready, failed, ab;
 unsigned int views;
};
static struct workqueue_struct *pn_wq;

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

/* HKDF-SHA256 with an arbitrary-length salt (v4 key schedule). */
static int pn_hkdf(struct piv_native *n, const u8 ikm[32], const u8 *salt, size_t salt_length,
		   const char *label, u8 out[32])
{
	u8 prk[32], info[48];
	size_t length = strlen(label);
	int r;
	if (length + 13 > sizeof(info)) return -EINVAL;
	memcpy(info, "pivstore/v4/", 12); memcpy(info + 12, label, length); info[12 + length] = 1;
	r = crypto_shash_setkey(n->hmac, salt, salt_length);
	if (!r) r = pn_hash(n->hmac, ikm, 32, prk);
	if (!r) r = crypto_shash_setkey(n->hmac, prk, 32);
	if (!r) r = pn_hash(n->hmac, info, 13 + length, out);
	memzero_explicit(prk, sizeof(prk));
	return r;
}

/* LRW-AES tweakable PRP over 16-byte IVs with tweak = primary sector. */
static void pn_v4_mask(const struct pn_lrw *k, u64 sector, u8 mask[16])
{
	u8 tweak[16] = {};
	put_unaligned_le64(sector, tweak);
	aes_encrypt(&k->tweak, mask, tweak);
}

static void pn_v4_encode(const struct pn_lrw *k, u64 sector, const u8 value[16], u8 iv[16])
{
	u8 mask[16], block[16];
	pn_v4_mask(k, sector, mask);
	crypto_xor_cpy(block, value, mask, 16);
	aes_encrypt(&k->prp, iv, block);
	crypto_xor(iv, mask, 16);
	memzero_explicit(block, sizeof(block));
}

static void pn_v4_decode(const struct pn_lrw *k, u64 sector, const u8 iv[16], u8 value[16])
{
	u8 mask[16], block[16];
	pn_v4_mask(k, sector, mask);
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

/* tag = HMAC-SHA256(mac, context || label(8|9) || LE64(id) || plain)[0:16] */
static int pn_v4_tag(struct piv_native *n, const u8 mac[32], const u8 *context, size_t context_length,
		     const char *label, u64 id, const u8 *plain, size_t plain_length, u8 tag[16])
{
	size_t label_length = strlen(label), length = context_length + label_length + 8 + plain_length;
	u8 *buffer = kmalloc(length, GFP_NOIO), digest[32];
	int r;
	if (!buffer) return -ENOMEM;
	memcpy(buffer, context, context_length);
	memcpy(buffer + context_length, label, label_length);
	put_unaligned_le64(id, buffer + context_length + label_length);
	memcpy(buffer + context_length + label_length + 8, plain, plain_length);
	r = crypto_shash_setkey(n->hmac, mac, 32);
	if (!r) r = pn_hash(n->hmac, buffer, length, digest);
	if (!r) memcpy(tag, digest, 16);
	memzero_explicit(digest, sizeof(digest));
	kfree_sensitive(buffer);
	return r;
}

/* ChaCha20(enc, counter 0, nonce = tag[0:12]) in place on a heap buffer. */
/* ChaCha20 keystream XOR over @buffer. Callers may pass stack memory, which a
 * scatterlist must never reference (VMAP_STACK: virt_to_page() of a vmalloc
 * address names the wrong page; CONFIG_DEBUG_SG BUG()s). Bounce through the
 * linear heap. Found by the KASAN/DEBUG_SG sanitizer guest (2026-10-21).
 */
static int pn_v4_stream(struct piv_native *n, const u8 enc[32], const u8 tag[16], u8 *buffer, size_t length)
{
	struct skcipher_request *req;
	struct scatterlist sg;
	DECLARE_CRYPTO_WAIT(wait);
	u8 iv[16] = {}, *bounce;
	int r = crypto_skcipher_setkey(n->chacha, enc, 32);
	if (r) return r;
	bounce = kmemdup(buffer, length, GFP_NOIO);
	req = skcipher_request_alloc(n->chacha, GFP_NOIO);
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

/* SIV over fragments: payload = tag || ChaCha20(plain) || zero padding, carried
 * as the 6-byte suffixes of @count LRW-decoded IVs starting at @first.
 * PN_UNAVAILABLE if padding or tag do not verify.
 */
static int pn_siv_open(struct piv_native *n, const struct pn_lrw *k, const u8 mac[32], const u8 enc[32],
		       const u8 *context, size_t context_length, const char *label, u64 id,
		       u64 first, u32 count, const u8 *ivs, u8 *plain, size_t plain_length)
{
	size_t bytes = count * PN_V4_FRAGMENT;
	u8 *payload = kmalloc(bytes, GFP_NOIO), value[16], tag[16];
	u32 j;
	int r;
	if (!payload) return -ENOMEM;
	for (j = 0; j < count; j++) {
		pn_v4_decode(k, first + j, ivs + j * 16, value);
		memcpy(payload + j * PN_V4_FRAGMENT, value + PN_V4_RANDOM, PN_V4_FRAGMENT);
	}
	memzero_explicit(value, sizeof(value));
	r = memchr_inv(payload + 16 + plain_length, 0, bytes - 16 - plain_length) ? PN_UNAVAILABLE : 0;
	if (!r) {
		memcpy(plain, payload + 16, plain_length);
		r = pn_v4_stream(n, enc, payload, plain, plain_length);
	}
	if (!r) r = pn_v4_tag(n, mac, context, context_length, label, id, plain, plain_length, tag);
	if (!r && crypto_memneq(tag, payload, 16)) r = PN_UNAVAILABLE;
	if (r) memzero_explicit(plain, plain_length);
	kfree_sensitive(payload);
	return r;
}

/* Fresh fragments for @plain: @ivs receives @count new IVs from @first. */
static int pn_siv_seal(struct piv_native *n, const struct pn_lrw *k, const u8 mac[32], const u8 enc[32],
		       const u8 *context, size_t context_length, const char *label, u64 id,
		       u64 first, u32 count, const u8 *plain, size_t plain_length, u8 *ivs)
{
	size_t bytes = count * PN_V4_FRAGMENT;
	u8 *payload = kzalloc(bytes, GFP_NOIO), value[16];
	u32 j;
	int r;
	if (!payload) return -ENOMEM;
	r = pn_v4_tag(n, mac, context, context_length, label, id, plain, plain_length, payload);
	if (!r) {
		memcpy(payload + 16, plain, plain_length);
		r = pn_v4_stream(n, enc, payload, payload + 16, plain_length);
	}
	for (j = 0; !r && j < count; j++) {
		get_random_bytes(value, PN_V4_RANDOM);
		memcpy(value + PN_V4_RANDOM, payload + j * PN_V4_FRAGMENT, PN_V4_FRAGMENT);
		pn_v4_encode(k, first + j, value, ivs + j * 16);
	}
	memzero_explicit(value, sizeof(value));
	kfree_sensitive(payload);
	return r;
}

/* Groups follow the 112 keyslot sectors; groups 0-1 are the directory. Block i
 * uses group 2+i, or groups 2+2i/3+2i (slots A/B) with A/B.
 */
static u64 pn_v4_group_first(u64 group) { return PN_V4_KEYSLOT_AREA + group * PN_V4_GROUP; }
static u64 pn_v4_group(struct piv_native *n, u64 index, u32 slot)
{
	return 2 + (n->ab ? 2 * index + slot : index);
}
/* First sector after the last record group; [PN_V4_KEYSLOT_AREA, end) carries
 * directory and record fragments under the master-key outer keys.
 */
static u64 pn_v4_area_end(struct piv_native *n)
{
	return pn_v4_group_first(2 + (n->ab ? 2 * n->records : n->records));
}

static int pn_v4_unpack(struct piv_native *n, u64 group, const u8 *ivs, u8 *data, u64 *generation)
{
	u8 *plain = kmalloc(PN_V4_PLAIN, GFP_NOIO);
	int r;
	if (!plain) return -ENOMEM;
	r = pn_siv_open(n, &n->rec, n->mac_key, n->enc_key, n->context, n->context_length, "/record/",
			group, pn_v4_group_first(group), PN_V4_GROUP, ivs, plain, PN_V4_PLAIN);
	if (!r) memcpy(data, plain + 8, PN_DATA);
	if (!r && generation) *generation = get_unaligned_le64(plain);
	kfree_sensitive(plain);
	return r;
}

static int pn_v4_pack(struct piv_native *n, u64 group, u64 generation, const u8 *data, u8 *ivs)
{
	u8 *plain = kmalloc(PN_V4_PLAIN, GFP_NOIO);
	int r;
	if (!plain) return -ENOMEM;
	put_unaligned_le64(generation, plain);
	memcpy(plain + 8, data, PN_DATA);
	r = pn_siv_seal(n, &n->rec, n->mac_key, n->enc_key, n->context, n->context_length, "/record/",
			group, pn_v4_group_first(group), PN_V4_GROUP, plain, PN_V4_PLAIN, ivs);
	kfree_sensitive(plain);
	return r;
}

/* Keyslot keys from a KEK (salt = base context, without the A/B suffix). */
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
static u64 pn_ks_first(u32 slot, u32 replica) { return (2 * slot + replica) * PN_V4_KEYSLOT_SECTORS; }

/* Keyslot plaintext: LE32 version 4 || LE32 flags || MK[32] || zero[24]. */
static int pn_ks_open(struct piv_native *n, const struct pn_ks_keys *k, u32 slot, u32 replica,
		      const u8 *ivs, u32 *flags, u8 master[32])
{
	u8 plain[PN_V4_KEYSLOT_PLAIN];
	int r = pn_siv_open(n, &k->lrw, k->mac, k->enc, n->base, n->base_length, "/keyslot/",
			    2 * slot + replica, pn_ks_first(slot, replica), PN_V4_KEYSLOT_SECTORS, ivs,
			    plain, sizeof(plain));
	if (!r && (get_unaligned_le32(plain) != 4 || (get_unaligned_le32(plain + 4) & ~PN_V4_FLAG_AB) ||
		   memchr_inv(plain + 40, 0, 24)))
		r = PN_UNAVAILABLE;
	if (!r) { *flags = get_unaligned_le32(plain + 4); memcpy(master, plain + 8, 32); }
	memzero_explicit(plain, sizeof(plain));
	return r;
}

static int pn_ks_seal(struct piv_native *n, const struct pn_ks_keys *k, u32 slot, u32 replica, u8 *ivs)
{
	u8 plain[PN_V4_KEYSLOT_PLAIN] = {};
	int r;
	put_unaligned_le32(4, plain);
	put_unaligned_le32(n->ab ? PN_V4_FLAG_AB : 0, plain + 4);
	memcpy(plain + 8, n->key, 32);
	r = pn_siv_seal(n, &k->lrw, k->mac, k->enc, n->base, n->base_length, "/keyslot/",
			2 * slot + replica, pn_ks_first(slot, replica), PN_V4_KEYSLOT_SECTORS, plain,
			sizeof(plain), ivs);
	memzero_explicit(plain, sizeof(plain));
	return r;
}

/* Directory data: per keyslot j, present byte || outer tweak key || outer prp key. */
static void pn_dir_build(struct piv_native *n, u8 *data)
{
	u32 j;
	memset(data, 0, PN_DATA);
	for (j = 0; j < PN_V4_KEYSLOTS; j++) if (n->ks_present[j]) {
		data[j * 65] = 1;
		memcpy(data + j * 65 + 1, n->ks_outer[j], 64);
	}
}

static int pn_dir_parse(struct piv_native *n, const u8 *data)
{
	u32 j;
	if (memchr_inv(data + PN_V4_KEYSLOTS * 65, 0, PN_DATA - PN_V4_KEYSLOTS * 65)) return -EUCLEAN;
	for (j = 0; j < PN_V4_KEYSLOTS; j++) {
		const u8 *e = data + j * 65;
		if (e[0] > 1 || (!e[0] && memchr_inv(e + 1, 0, 64))) return -EUCLEAN;
		n->ks_present[j] = e[0];
		memcpy(n->ks_outer[j], e + 1, 64);
		if (e[0] && pn_lrw_init(&n->ks_lrw[j], e + 1, e + 33)) return -EUCLEAN;
	}
	return 0;
}

/* Decoy-write rule: keep the 6 payload bytes of the old IV, refresh the 10 random bytes. */
static void pn_v4_refresh(const struct pn_lrw *k, u64 sector, const u8 old[16], u8 iv[16])
{
	u8 value[16];
	do {
		pn_v4_decode(k, sector, old, value);
		get_random_bytes(value, PN_V4_RANDOM);
		pn_v4_encode(k, sector, value, iv);
	} while (!memcmp(iv, old, 16));
	memzero_explicit(value, sizeof(value));
}

/* New IV for a decoy-written sector: fragment refresh where a keyslot (known
 * from the directory), the directory or a record lives; otherwise random.
 */
static void pn_v4_decoy_iv(struct piv_native *n, u64 sector, const u8 old[16], u8 iv[16])
{
	if (sector < PN_V4_KEYSLOT_AREA) {
		u32 slot = sector / (2 * PN_V4_KEYSLOT_SECTORS);
		if (n->ks_present[slot]) { pn_v4_refresh(&n->ks_lrw[slot], sector, old, iv); return; }
	} else if (sector < pn_v4_area_end(n)) {
		pn_v4_refresh(&n->rec, sector, old, iv);
		return;
	}
	do get_random_bytes(iv, 16); while (!memcmp(iv, old, 16));
}

/* IVs of @count sectors from @index (one bounded range). With @tolerant, a
 * range failing primary authentication falls back to per-sector loads and
 * takes the raw stored IV of each failing sector. Only SIV-checked decoding
 * (keyslots, the directory, hidden reads) may use that: its tag rejects any
 * damaged, missing or mixed fragment, so nothing unauthenticated is accepted.
 */
static int pn_range_ivs(struct piv_control *p, u64 index, u32 count, u8 *ivs, bool tolerant)
{
 u32 j, iv = p->profile.iv_size;
 int r = piv_read_range(p, index, count, NULL, ivs);
 if (r != -EBADMSG || !tolerant) return r;
 for (j = 0; j < count; j++) {
  struct piv_sector *s = NULL;
  r = piv_load_mode(p->cc, index + j, &s, true); if (r) return r;
  memcpy(ivs + j * iv, s->original + 4112, iv);
  piv_sector_free(p->cc, s);
 }
 return 0;
}

/* Authenticate primary data before accepting its carrier, even for replacement
 * (strict: writes need the authenticated old sectors). Reads pass @tolerant.
 */
static int pn_carrier_mode(struct piv_control *p, u64 first, u32 group, u8 *carrier, bool tolerant)
{
 u32 j = 0, iv = p->profile.iv_size;
 while (j < group) {
  u32 count = min_t(u32, group - j, PIV_READ_BYTES / p->profile.sector_size);
  int r = pn_range_ivs(p, first + j, count, carrier + j * iv, tolerant);
  if (r) return r;
  j += count;
 }
 return 0;
}
static int pn_carrier_at(struct piv_control *p, u64 first, u32 group, u8 *carrier)
{
 return pn_carrier_mode(p, first, group, carrier, false);
}
/* Read block i's record(s). With A/B, *slot returns the newest valid slot (or
 * -1 if none) and *generation its generation; @carrier needs 2 * 1440 bytes.
 * Returns PN_UNAVAILABLE when no slot authenticates.
 */
static int pn_v4_read(struct piv_control *p, u64 index, u8 *carrier, u8 *data, int *slot, u64 *generation)
{
 struct piv_native *n = p->native;
 u32 i, slots = n->ab ? 2 : 1;
 u64 best = 0, found;
 int r, chosen = -1;
 u8 *candidate = kmalloc(PN_DATA, GFP_NOIO);
 if (!candidate) return -ENOMEM;
 for (i = 0; i < slots; i++) {
  u64 group = pn_v4_group(n, index, i);
  /* Hidden decoding only needs the IVs; the record's SIV tag decides. */
  r = pn_carrier_mode(p, pn_v4_group_first(group), PN_V4_GROUP, carrier + i * PN_V4_CARRIER, true);
  if (!r) r = pn_v4_unpack(n, group, carrier + i * PN_V4_CARRIER, candidate, &found);
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
 return pn_v4_read(p, index, carrier, data, NULL, NULL);
}
static void pn_free(struct piv_native *n)
{
 if (!n) return;
 if (!IS_ERR_OR_NULL(n->hmac)) crypto_free_shash(n->hmac);
 if (!IS_ERR_OR_NULL(n->chacha)) crypto_free_skcipher(n->chacha);
 kfree_sensitive(n);
}

/* Prepare every fresh tuple, then apply them through the lower journal. Entries
 * hold the authenticated old IVs; ivs the replacements. Decoy sectors inside
 * [offset, offset + bytes) merge requested bytes after authenticating old data.
 */
static int pn_commit(struct piv_control *p, bool hidden, u64 offset, const u8 *data, u32 bytes,
		     struct pn_entry *entries, const u8 *ivs, u32 count, bool *mutated)
{
 struct piv_update *u = kzalloc(sizeof(*u), GFP_NOIO);
 u32 iv = p->profile.iv_size, i;
 u64 unit = p->profile.sector_size;
 int r = 0;
 if (!u) return -ENOMEM;
 u->version = PIV_CONTROL_VERSION; u->size = sizeof(*u); u->generation = p->profile.generation;
 /* Prepare every tuple before the first mutation. No external WAL/replay. */
 for (i = 0; i < count; i++) {
  u64 sector = le64_to_cpu(entries[i].sector), start = sector * unit;
  bool primary = !hidden && start < offset + bytes && start + unit > offset;
  memset(u->tuple, 0, sizeof(u->tuple)); u->sector = sector;
  memcpy(u->expected_iv, entries[i].old, iv); memcpy(u->tuple + 4112, ivs + i * iv, iv);
  if (primary) {
   struct piv_sector *s = NULL;
   u64 lo = max(start, offset), hi = min(start + unit, offset + bytes);
   /* A replaced sector is fully covered by the request; nothing to merge. */
   if (!entries[i].replace) {
    r = piv_load(p->cc, sector, &s); if (r) goto done;
    memcpy(u->tuple, page_address(s->page), unit); piv_sector_free(p->cc, s);
   }
   memcpy(u->tuple + lo - start, data + lo - offset, hi - lo);
   entries[i].primary = cpu_to_le32(1);
  }
  r = piv_update(p, NULL, u, true, primary, true, entries[i].replace); if (r) goto done;
  memcpy(entries[i].tuple, u->tuple, PIV_TUPLE_BYTES);
 }
 u->flags = PIV_APPLY_DEFER_FLUSH;
 /* Conservative: any APPLY-loop failure may follow a lower write. */
 *mutated = true;
 for (i = 0; i < count; i++) {
  u->sector = le64_to_cpu(entries[i].sector);
  memcpy(u->expected_iv, entries[i].old, iv); memcpy(u->tuple, entries[i].tuple, PIV_TUPLE_BYTES);
  r = piv_update(p, NULL, u, false, le32_to_cpu(entries[i].primary), true, entries[i].replace);
  if (r) goto done;
  if ((i + 1) % 32 == 0) { r = blkdev_issue_flush(p->cc->dev->bdev); if (r) goto done; }
 }
 r = blkdev_issue_flush(p->cc->dev->bdev);
done:
 kfree_sensitive(u);
 return r;
}

/* Replace @count IVs from @first with @fresh (hidden-only tuples: primary
 * plaintext unchanged). Old IVs are read and authenticated first. -EEXIST if a
 * fresh IV repeats an old or another fresh one (callers re-encode and retry).
 */
static int pn_v4_replace(struct piv_control *p, u64 first, u32 count, const u8 *fresh, bool *mutated)
{
 struct pn_entry *entries = kvcalloc(PN_MAX_ENTRIES, sizeof(*entries), GFP_NOIO);
 u8 *olds = kmalloc(PN_MAX_ENTRIES * 16, GFP_NOIO);
 u32 i, j;
 int r = -ENOMEM;
 if (!entries || !olds) goto done;
 r = -E2BIG;
 if (!count || count > PN_MAX_ENTRIES) goto done;
 r = pn_carrier_at(p, first, count, olds); if (r) goto done;
 r = -EEXIST;
 for (i = 0; i < count; i++) {
  entries[i].sector = cpu_to_le64(first + i);
  memcpy(entries[i].old, olds + i * 16, 16);
  for (j = 0; j < count; j++) if (!memcmp(fresh + i * 16, olds + j * 16, 16)) goto done;
  for (j = 0; j < i; j++) if (!memcmp(fresh + i * 16, fresh + j * 16, 16)) goto done;
 }
 r = -EDQUOT;
 if (count > (1ULL << 32) - p->encryptions) goto done;
 r = pn_commit(p, true, 0, NULL, 0, entries, fresh, count, mutated);
done:
 kvfree_sensitive(entries, PN_MAX_ENTRIES * sizeof(*entries));
 kfree_sensitive(olds);
 return r;
}

/* Encode and write one record group, retrying local IV collisions. */
static int pn_v4_write_group(struct piv_control *p, u64 group, u64 generation, const u8 *data, bool *mutated)
{
 u8 *ivs = kmalloc(PN_V4_CARRIER, GFP_NOIO);
 u32 attempt;
 int r = -ENOMEM;
 if (!ivs) return r;
 for (attempt = 0; attempt < 16; attempt++) {
  r = pn_v4_pack(p->native, group, generation, data, ivs);
  if (!r) r = pn_v4_replace(p, pn_v4_group_first(group), PN_V4_GROUP, ivs, mutated);
  if (r != -EEXIST || *mutated) break;
 }
 kfree_sensitive(ivs);
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
 r = pn_v4_write_group(p, slot, n->dir_generation + 1, data, mutated);
 if (!r) { n->dir_slot = slot; n->dir_generation++; }
 kfree_sensitive(data);
 return r;
}

/* Write keyslot @slot (both replicas) under @kek, or overwrite it with fresh
 * random IVs when @kek is NULL.
 */
static int pn_ks_write(struct piv_control *p, u32 slot, const u8 *kek, struct pn_ks_keys *keys, bool *mutated)
{
 u8 *ivs = kmalloc(PN_V4_KEYSLOT_SECTORS * 16, GFP_NOIO);
 u32 replica, attempt;
 int r = -ENOMEM;
 if (!ivs) return r;
 for (replica = 0; replica < 2; replica++) {
  for (attempt = 0; attempt < 16; attempt++) {
   if (kek) r = pn_ks_seal(p->native, keys, slot, replica, ivs);
   else { get_random_bytes(ivs, PN_V4_KEYSLOT_SECTORS * 16); r = 0; }
   if (!r) r = pn_v4_replace(p, pn_ks_first(slot, replica), PN_V4_KEYSLOT_SECTORS, ivs, mutated);
   if (r != -EEXIST || *mutated) break;
  }
  if (r) break;
 }
 kfree_sensitive(ivs);
 return r;
}

/* Format v4 write. A hidden write re-encodes its whole record (with A/B, into
 * the slot not holding the newest valid version); a decoy write re-randomizes
 * only the IVs of the primary sectors it writes, preserving their fragments.
 */
static int pn_write_v4(struct piv_control *p, bool hidden, u64 offset, const u8 *data, u32 bytes,
		       bool *mutated)
{
 struct piv_native *n = p->native;
 struct pn_entry *entries;
 u8 *ivs, *scratch;
 u64 unit = p->profile.sector_size, index, generation = 0;
 u32 count = 0, i, j, attempt;
 int slot = 0, r;
 if (hidden) {
  if (bytes != PN_DATA || offset % PN_DATA || offset / PN_DATA >= n->records) return -EINVAL;
  index = offset / PN_DATA;
  if (n->ab) {
   scratch = kmalloc(2 * PN_V4_CARRIER + PN_DATA, GFP_NOIO);
   if (!scratch) return -ENOMEM;
   r = pn_v4_read(p, index, scratch, scratch + 2 * PN_V4_CARRIER, &slot, &generation);
   kfree_sensitive(scratch);
   if (r && r != PN_UNAVAILABLE) return r;
   slot = (r || slot < 0) ? 0 : !slot;
   generation = r ? 1 : generation + 1;
   if (!generation) return -EOVERFLOW;
  }
  return pn_v4_write_group(p, pn_v4_group(n, index, slot), generation, data, mutated);
 }
 entries = kvcalloc(PN_MAX_ENTRIES, sizeof(*entries), GFP_NOIO);
 ivs = kmalloc(PN_MAX_ENTRIES * 16, GFP_NOIO);
 r = -ENOMEM;
 if (!entries || !ivs) goto done;
 for (index = offset / unit; index <= (offset + bytes - 1) / unit; index++) {
  struct piv_sector *s = NULL;
  /* A sector failing authentication (e.g. torn without the journal) may be
   * replaced only by a write covering all of it. Its raw stored fragment is
   * refreshed like any other: the record's SIV tag decides whether it is
   * still valid, so damage stays damage and is never made authentic.
   */
  bool full = index * unit >= offset && (index + 1) * unit <= offset + bytes;
  if (count == PN_MAX_ENTRIES) { r = -E2BIG; goto done; }
  r = piv_load_mode(p->cc, index, &s, full); if (r) goto done;
  entries[count].sector = cpu_to_le64(index);
  entries[count].replace = s->bad;
  memcpy(entries[count++].old, s->original + 4112, 16); piv_sector_free(p->cc, s);
 }
 if (!count || count > (1ULL << 32) - p->encryptions) { r = -EDQUOT; goto done; }
 /* Local checks are NOT a historical nonce-uniqueness guarantee. */
 for (attempt = 0; attempt < 16; attempt++) {
  bool collision = false;
  for (i = 0; i < count; i++)
   pn_v4_decoy_iv(n, le64_to_cpu(entries[i].sector), entries[i].old, ivs + i * 16);
  for (i = 0; i < count; i++) {
   for (j = 0; j < count; j++) if (!memcmp(ivs + i * 16, entries[j].old, 16)) collision = true;
   for (j = 0; j < i; j++) if (!memcmp(ivs + i * 16, ivs + j * 16, 16)) collision = true;
  }
  if (!collision) break;
 }
 if (attempt == 16) { r = -EEXIST; goto done; }
 r = pn_commit(p, false, offset, data, bytes, entries, ivs, count, mutated);
done:
 kvfree_sensitive(entries, PN_MAX_ENTRIES * sizeof(*entries));
 kfree_sensitive(ivs);
 return r;
}

/* noinline: kprobe-based lifecycle/profile/cancel tests attach to pn_write.
 * *mutated reports whether storage may have changed. Every failure before that
 * point leaves the disk untouched; the caller may then fail only this request.
 */
static noinline int pn_write(struct piv_control *p, bool hidden, u64 offset, const u8 *data, u32 bytes,
			     bool *mutated)
{
 return pn_write_v4(p, hidden, offset, data, bytes, mutated);
}

/* Cooperative setup only: never interrupt an in-flight hidden-record write.
 * Completed initialization records remain committed; cancellation is not undo.
 */
static int pn_setup_poll(void)
{
 cond_resched();
 return signal_pending(current) ? -EINTR : 0;
}

/* v4 record keys from the master key; context = base (+ "/ab"). */
static int pn_v4_keys(struct piv_native *n, u64 sectors)
{
 u8 tweak[32], prp[32];
 int r;
 memcpy(n->context, n->base, n->base_length);
 n->context_length = n->base_length;
 if (n->ab) { memcpy(n->context + n->context_length, "/ab", 3); n->context_length += 3; }
 n->records = (sectors - PN_V4_RESERVED) / PN_V4_GROUP;
 if (n->ab) n->records /= 2;
 if (!n->records) return -EINVAL;
 n->hidden_bytes = n->records * PN_DATA;
 r = pn_hkdf(n, n->key, n->context, n->context_length, "tweak", tweak);
 if (!r) r = pn_hkdf(n, n->key, n->context, n->context_length, "prp", prp);
 if (!r) r = pn_lrw_init(&n->rec, tweak, prp);
 if (!r) r = pn_hkdf(n, n->key, n->context, n->context_length, "mac", n->mac_key);
 if (!r) r = pn_hkdf(n, n->key, n->context, n->context_length, "enc", n->enc_key);
 memzero_explicit(tweak, sizeof(tweak)); memzero_explicit(prp, sizeof(prp));
 return r;
}

/* Fast key check: try every keyslot replica under the KEK. 0 on success with
 * n->key = master key and n->ab set; PN_UNAVAILABLE if none authenticates.
 */
static int pn_v4_unlock(struct piv_native *n, const u8 kek[32], const u8 *ks_ivs)
{
 struct pn_ks_keys *k = kzalloc(sizeof(*k), GFP_NOIO);
 u32 slot, replica, flags = 0;
 u8 master[32];
 int r;
 if (!k) return -ENOMEM;
 r = pn_ks_derive(n, kek, k);
 for (slot = 0; !r && slot < PN_V4_KEYSLOTS; slot++)
  for (replica = 0; replica < 2; replica++) {
   r = pn_ks_open(n, k, slot, replica, ks_ivs + pn_ks_first(slot, replica) * 16, &flags, master);
   if (r != PN_UNAVAILABLE) goto out;
   r = 0;
  }
 r = r ? r : PN_UNAVAILABLE;
out:
 if (!r) { memcpy(n->key, master, 32); n->ab = flags & PN_V4_FLAG_AB; }
 memzero_explicit(master, sizeof(master));
 kfree_sensitive(k);
 return r;
}

/* Read the directory (newest valid of groups 0/1) and load keyslot outer keys. */
static int pn_dir_load(struct piv_control *p)
{
 struct piv_native *n = p->native;
 u8 *carrier = kmalloc(PN_V4_CARRIER + PN_DATA, GFP_NOIO);
 u64 generation;
 int r, slot;
 n->dir_slot = -1;
 if (!carrier) return -ENOMEM;
 for (slot = 0; slot < 2; slot++) {
  r = pn_carrier_mode(p, pn_v4_group_first(slot), PN_V4_GROUP, carrier, true);
  if (!r) r = pn_v4_unpack(n, slot, carrier, carrier + PN_V4_CARRIER, &generation);
  if (r == PN_UNAVAILABLE || r == -EBADMSG) continue;
  if (r) goto out;
  if (n->dir_slot < 0 || generation > n->dir_generation) {
   r = pn_dir_parse(n, carrier + PN_V4_CARRIER);
   if (r) goto out;
   n->dir_slot = slot; n->dir_generation = generation;
  }
 }
 /* Without a directory, decoy writes would destroy other keyslots: refuse. */
 r = n->dir_slot < 0 ? -EUCLEAN : 0;
out:
 kfree_sensitive(carrier);
 return r;
}

/* Fast key check once the scan has collected every keyslot IV (no extra I/O),
 * then the record keys and the directory: decoy writes must refresh every
 * keyslot it lists, so setup refuses without it.
 */
static int pn_setup_unlock(struct piv_control *p, struct piv_native *n, const u8 key[32], const u8 *ks_ivs)
{
 int r = pn_v4_unlock(n, key, ks_ivs);
 if (r == PN_UNAVAILABLE) return -EKEYREJECTED;
 if (!r) r = pn_v4_keys(n, p->profile.sectors);
 if (!r) r = pn_dir_load(p);
 return r;
}

static int pn_setup(struct piv_control *p, struct file *controller, struct piv_native_setup *s)
{
 struct piv_native *n;
 u8 *zero, *ivs = NULL, *ks_ivs = NULL;
 u64 i;
 u32 j;
 bool initialize = s->flags & PIV_SETUP_INITIALIZE, ab = s->flags & PIV_SETUP_AB, mutated, ks_done = false;
 bool verify = s->flags & PIV_SETUP_VERIFY;
 u64 scan_end;
 int r;
 if (s->version != 4 || s->size != sizeof(*s) || s->generation != p->profile.generation ||
     s->context_length > 120 || s->context_length <= 19 ||
     memcmp(s->context, "pivstore/volume/v4", 19) ||
     (s->flags & ~(PIV_SETUP_INITIALIZE | PIV_SETUP_AB | PIV_SETUP_VERIFY)) ||
     memchr_inv(s->reserved, 0, sizeof(s->reserved))) return -EINVAL;
 /* Format v4 needs 16-byte IVs (AEGIS-128). A/B is chosen at initialization
  * and afterwards read from the keyslot.
  */
 if (p->profile.iv_size != 16 || (ab && !initialize)) return -EINVAL;
 if (p->native || !piv_quiesced(p) || !p->transaction || p->controller != controller || p->failed) return -EBUSY;
 /* Bound every primary byte offset by the kernel's signed file limit.
  * Fragment indices, hidden capacity and 512-byte addresses are then smaller;
  * all per-request allocations remain bounded independently of volume size.
  */
 if (p->profile.sectors < PN_V4_RESERVED + PN_V4_GROUP * (ab ? 2 : 1) ||
     p->profile.sectors > (u64)MAX_LFS_FILESIZE / p->profile.sector_size) return -EINVAL;
 n = kzalloc(sizeof(*n), GFP_NOIO); if (!n) return -ENOMEM;
 memcpy(n->key, s->key, 32);
 memcpy(n->base, s->context, s->context_length);
 n->base_length = s->context_length;
 n->dir_slot = -1;
 n->hmac = crypto_alloc_shash("hmac(sha256)", 0, 0);
 n->chacha = crypto_alloc_skcipher("chacha20", 0, 0);
 if (IS_ERR(n->hmac) || IS_ERR(n->chacha)) { r = -ENOENT; goto bad; }
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
 scan_end = verify ? p->profile.sectors : PN_V4_KEYSLOT_AREA;
 ivs = kmalloc(PIV_READ_BYTES / 512 * 16, GFP_NOIO);
 if (!initialize) ks_ivs = kzalloc(PN_V4_KEYSLOT_AREA * 16, GFP_NOIO);
 if (!ivs || (!initialize && !ks_ivs)) { r = -ENOMEM; goto bad; }
 for (i = 0; i < scan_end;) {
  u32 count = min_t(u64, scan_end - i, PIV_READ_BYTES / p->profile.sector_size);
  r = pn_setup_poll(); if (r) goto bad;
  r = pn_range_ivs(p, i, count, ivs, !verify); if (r) goto bad;
  for (j = 0; ks_ivs && j < count && i + j < PN_V4_KEYSLOT_AREA; j++)
   memcpy(ks_ivs + (i + j) * 16, ivs + j * 16, 16);
  i += count;
  /* Unlock as soon as the keyslot area is collected (sectors >= RESERVED). */
  if (ks_ivs && !ks_done && i >= PN_V4_KEYSLOT_AREA) {
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
  r = pn_ks_derive(n, s->key, k);
  get_random_bytes(n->key, 32);
  if (!r) r = pn_v4_keys(n, p->profile.sectors);
  if (!r) {
   n->ks_present[0] = true;
   memcpy(n->ks_outer[0], k->tweak, 32); memcpy(n->ks_outer[0] + 32, k->prp, 32);
   n->ks_lrw[0] = k->lrw;
   r = pn_ks_write(p, 0, s->key, k, &mutated);
  }
  kfree_sensitive(k);
  if (!r) r = pn_dir_write(p, &mutated);
  if (r) goto bad;
  zero = kzalloc(PN_DATA, GFP_NOIO);
  if (!zero) { r = -ENOMEM; goto bad; }
  for (i = 0; i < n->hidden_bytes / PN_DATA; i++) {
   r = pn_setup_poll(); if (r) break;
   r = pn_write(p, true, i * PN_DATA, zero, PN_DATA, &mutated); if (r) break;
  }
  kfree_sensitive(zero); if (r) goto bad;
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

/* Add or remove a v4 keyslot on an active owner. The master key stays in
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
     ks->slot >= PN_V4_KEYSLOTS || (ks->op != PIV_KEYSLOT_ADD && ks->op != PIV_KEYSLOT_REMOVE) ||
     memchr_inv(ks->reserved, 0, sizeof(ks->reserved)) ||
     (ks->op == PIV_KEYSLOT_REMOVE && memchr_inv(ks->kek, 0, sizeof(ks->kek)))) return -EINVAL;
 if (!n || !n->ready || n->failed || p->failed || p->blocked) return -EBUSY;
 for (j = 0; j < PN_V4_KEYSLOTS; j++) present += n->ks_present[j];
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
 if (r && mutated) { p->failed = true; n->failed = true; }
 return r;
}

static int pn_read(struct piv_control *p, bool hidden, u64 offset, u8 *data, u32 bytes)
{
 u64 unit = hidden ? PN_DATA : p->profile.sector_size, first = offset / unit, last = (offset + bytes - 1) / unit, i;
 u8 *record = kmalloc(hidden ? PN_MAX_CARRIER + PN_DATA : PIV_READ_BYTES, GFP_NOIO);
 int r = 0;
 if (!record) return -ENOMEM;
 for (i = first; i <= last; i++) {
  u64 start = i * unit, lo = max(start, offset), hi = min(start + unit, offset + bytes);
  if (hidden) {
   r = pn_read_record(p, i, record, record + PN_MAX_CARRIER); if (r) break;
   memcpy(data + lo - offset, record + PN_MAX_CARRIER + lo - start, hi - lo);
  } else {
   u32 count = min_t(u64, last - i + 1, PIV_READ_BYTES / unit);
   r = piv_read_range(p, i, count, record, NULL); if (r) break;
   hi = min(start + count * unit, offset + bytes);
   memcpy(data + lo - offset, record + lo - start, hi - lo);
   i += count - 1;
  }
 }
 kfree_sensitive(record); return r;
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

static void pn_worker(struct work_struct *work)
{
	struct pn_work *w = container_of(work, struct pn_work, work);
	struct piv_control *p = w->p;
	struct bio *bio = w->bio;
	u32 bytes = bio->bi_iter.bi_size;
	u8 *buffer = NULL;
	unsigned int noio;
	bool mutated = false, flushing = false;
	int r = -EIO;
	mutex_lock(&p->lock); noio = memalloc_noio_save();
	if (!p->live || !p->native || !p->native->ready || p->native->failed ||
	    p->blocked || p->transaction || p->failed) goto done;
	if (!bytes && (bio_op(bio) == REQ_OP_FLUSH || (bio->bi_opf & REQ_PREFLUSH))) {
		flushing = true;
		r = blkdev_issue_flush(p->cc->dev->bdev);
	} else {
		u64 limit = w->hidden ? p->native->hidden_bytes : p->profile.sectors * p->profile.sector_size;
		if (!bytes || bytes > (w->hidden ? PN_DATA : PN_DECOY_BYTES) || (w->offset & 511) ||
		    (bytes & 511) || w->offset > limit || bytes > limit - w->offset) { r = -EINVAL; goto done; }
		buffer = kmalloc(bytes, GFP_NOIO);
		if (!buffer) { r = -ENOMEM; goto done; }
		if (bio_op(bio) == REQ_OP_READ) {
			r = pn_read(p, w->hidden, w->offset, buffer, bytes);
			if (!r) pn_copy_bio(bio, buffer, true);
		} else if (bio_op(bio) == REQ_OP_WRITE) {
			pn_copy_bio(bio, buffer, false);
			/* Drain earlier journal writes before a WRITE|PREFLUSH payload.
			 * pn_write flushes each batch before completion, satisfying FUA too.
			 */
			flushing = bio->bi_opf & REQ_PREFLUSH;
			r = flushing ? blkdev_issue_flush(p->cc->dev->bdev) : 0;
			if (!r) {
				flushing = false;
				r = pn_write(p, w->hidden, w->offset, buffer, bytes, &mutated);
			}
		} else r = -EOPNOTSUPP;
	}
	/* Scoped isolation: reads, validation, authentication, allocation, nonce
	 * and preparation failures change no storage and fail only this bio. A
	 * failed flush leaves earlier durability unknown, and an APPLY-loop failure
	 * may have partially written; both still stop the shared owner.
	 */
	if (r < 0 && (mutated || flushing)) { p->failed = true; p->native->failed = true; }
done:
	kfree_sensitive(buffer); memalloc_noio_restore(noio); mutex_unlock(&p->lock);
	bio->bi_status = errno_to_blk_status(r > 0 ? -EIO : r); bio_endio(bio);
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
	if (!found->live || !found->native || !found->native->ready || found->native->failed ||
	    disk_devt(v->owner->bdev->bd_disk) != MKDEV(found->devices.owner_major, found->devices.owner_minor) ||
	    ti->begin || ti->len != (v->hidden ? found->native->hidden_bytes / 512 : found->profile.sectors * (found->profile.sector_size / 512)) ||
	    (found->native->views & (v->hidden ? 2 : 1))) r = -EINVAL;
	else { found->native->views |= v->hidden ? 2 : 1; r = 0; }
	mutex_unlock(&found->lock);
	if (r) { dm_put_device(ti, v->owner); goto free_ref; }
	ti->private = v; ti->num_flush_bios = 1;
	r = dm_set_target_max_io_len(ti, v->hidden ? 1 : PN_DECOY_BYTES / 512);
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
	/* Authenticated primary-sector RMW permits 512-byte logical requests. */
	limits->logical_block_size = 512;
	limits->physical_block_size = v->p->profile.sector_size;
	limits->io_min = v->p->profile.sector_size; limits->dma_alignment = 511;
}
static void pn_status(struct dm_target *ti, status_type_t type, unsigned int flags, char *result, unsigned int maxlen)
{
	struct pn_view *v = ti->private;
	unsigned int sz = 0;
	DMEMIT("%s %llu %s", v->owner->name, (unsigned long long)v->p->profile.generation, v->hidden ? "hidden" : "decoy");
}
static struct target_type piv_view_target = {
	.name = "piv-view", .version = {0, 3, 0}, .module = THIS_MODULE,
	.ctr = pn_ctr, .dtr = pn_dtr, .map = pn_map, .iterate_devices = pn_iterate,
	.io_hints = pn_hints, .status = pn_status,
};
