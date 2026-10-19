/* SPDX-License-Identifier: GPL-2.0-only */
/* Stateless paired views. Only stock dm-integrity persists recovery information.
 * Whole hidden blocks authenticate, but interrupted multi-sector writes can
 * destroy them. All work is serialized under the owner lock in NOIO context.
 */
/* Positive internal sentinel: -ENODATA may also mean a block medium error. */
#define PN_UNAVAILABLE 1
#define PN_DATA 512
#define PN_CARRIER 576
#define PN_MAX_ENTRIES 96
/* Power-of-two DM split boundary; <= one smallest carrier group (36 * 512).
 * An unaligned request can intersect at most two groups / 96 prepared tuples.
 * No cross-bio accumulation or delayed completion is used.
 */
#define PN_DECOY_BYTES 16384
struct pn_entry {
 __le64 sector;
 __le32 primary;
 u8 old[16], tuple[PIV_TUPLE_BYTES];
} __packed;
struct piv_native {
 struct crypto_aead *record_cipher;
 struct crypto_shash *hmac;
 u8 key[32], context[128];
 u32 context_length;
 u64 hidden_bytes, invalidations;
 bool ready, failed;
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

static int pn_derive(struct piv_native *n, const u8 salt[32],
		     const u8 *info, size_t length, u8 key[32])
{
	u8 prk[32], expand[160];
	int r;
	if (length + 1 > sizeof(expand)) return -EINVAL;
	r = crypto_shash_setkey(n->hmac, salt, 32);
	if (!r) r = pn_hash(n->hmac, n->key, 32, prk);
	if (!r) r = crypto_shash_setkey(n->hmac, prk, 32);
	memcpy(expand, info, length); expand[length] = 1;
	if (!r) r = pn_hash(n->hmac, expand, length + 1, key);
	memzero_explicit(prk, sizeof(prk));
	memzero_explicit(expand, sizeof(expand));
	return r;
}

/* kvmalloc buffers require page scatterlists, never sg_init_one(vmalloc). */
static int pn_aead(struct crypto_aead *tfm, const u8 key[32], void *buffer,
		   size_t associated, size_t plain, bool encrypt)
{
	struct sg_table table;
	struct aead_request *req;
	DECLARE_CRYPTO_WAIT(wait);
	u8 iv[12] = {};
	size_t bytes = associated + plain + 16, done = 0;
	unsigned int pages = DIV_ROUND_UP(offset_in_page(buffer) + bytes, PAGE_SIZE), i;
	struct scatterlist *sg;
	int r = sg_alloc_table(&table, pages, GFP_NOIO);
	if (r) return r;
	for_each_sg(table.sgl, sg, pages, i) {
		void *at = (u8 *)buffer + done;
		size_t size = min_t(size_t, bytes - done, PAGE_SIZE - offset_in_page(at));
		struct page *page = is_vmalloc_addr(at) ? vmalloc_to_page(at) : virt_to_page(at);
		sg_set_page(sg, page, size, offset_in_page(at)); done += size;
	}
	r = crypto_aead_setkey(tfm, key, 32);
	if (r) goto free_sg;
	req = aead_request_alloc(tfm, GFP_NOIO);
	if (!req) { r = -ENOMEM; goto free_sg; }
	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, &wait);
	aead_request_set_ad(req, associated);
	aead_request_set_crypt(req, table.sgl, table.sgl, plain + (encrypt ? 0 : 16), iv);
	r = crypto_wait_req(encrypt ? crypto_aead_encrypt(req) : crypto_aead_decrypt(req), &wait);
	aead_request_free(req);
free_sg:
	sg_free_table(&table);
	return r;
}


/* state 0 = data; state 1 = authenticated invalid marker with zero data.
 * PN_UNAVAILABLE is LOCAL hidden unavailability, never a primary auth failure.
 */
static int pn_record(struct piv_native *n, u64 index, u8 *carrier,
                     u8 *data, bool encrypt, bool invalid)
{
 u8 aad[160], key[32], *buffer;
 size_t length = n->context_length;
 int r;
 memcpy(aad, n->context, length);
 memcpy(aad + length, "/block/", 7); length += 7;
 put_unaligned_le64(index, aad + length); length += 8;
 if (encrypt) get_random_bytes(carrier, 32);
 r = pn_derive(n, carrier, aad, length, key);
 if (r) return r;
 buffer = kzalloc(length + 544, GFP_NOIO);
 if (!buffer) { memzero_explicit(key, 32); return -ENOMEM; }
 memcpy(buffer, aad, length);
 if (encrypt) {
  memcpy(buffer + length, "PIVBLK03", 8);
  put_unaligned_le64(invalid ? 1 : 0, buffer + length + 8);
  if (!invalid) memcpy(buffer + length + 16, data, PN_DATA);
 } else memcpy(buffer + length, carrier + 32, 544);
 r = pn_aead(n->record_cipher, key, buffer, length, 528, encrypt);
 if (!r && encrypt) memcpy(carrier + 32, buffer + length, 544);
 if (r == -EBADMSG) r = PN_UNAVAILABLE;
 if (!r && !encrypt) {
  if (memcmp(buffer + length, "PIVBLK03", 8) ||
      get_unaligned_le64(buffer + length + 8) != 0) r = PN_UNAVAILABLE;
  else memcpy(data, buffer + length + 16, PN_DATA);
 }
 memzero_explicit(key, 32); kfree_sensitive(buffer);
 return r;
}

/* Authenticate primary data before accepting its carrier, even for replacement. */
static int pn_carrier(struct piv_control *p, u64 index, u8 *carrier)
{
 u32 j, iv = p->profile.iv_size, group = PN_CARRIER / iv;
 for (j = 0; j < group; j++) {
  struct piv_sector *s = NULL;
  int r = piv_load(p->cc, index * group + j, &s);
  if (r) return r;
  memcpy(carrier + j * iv, s->original + 4112, iv);
  piv_sector_free(p->cc, s);
 }
 return 0;
}
static int pn_read_record(struct piv_control *p, u64 index, u8 *carrier, u8 *data)
{
 int r = pn_carrier(p, index, carrier);
 return r ? r : pn_record(p->native, index, carrier, data, false, false);
}
static void pn_free(struct piv_native *n)
{
 if (!n) return;
 if (!IS_ERR_OR_NULL(n->record_cipher)) crypto_free_aead(n->record_cipher);
 if (!IS_ERR_OR_NULL(n->hmac)) crypto_free_shash(n->hmac);
 kfree_sensitive(n);
}
struct pn_group { u64 index; bool invalid; u8 data[512], old[576], fresh[576]; };

static int pn_write(struct piv_control *p, bool hidden, u64 offset, const u8 *data, u32 bytes)
{
 struct piv_native *n = p->native;
 struct pn_group *groups = kcalloc(2, sizeof(*groups), GFP_NOIO);
 struct pn_entry *entries = kvcalloc(PN_MAX_ENTRIES, sizeof(*entries), GFP_NOIO);
 struct piv_update *u = kzalloc(sizeof(*u), GFP_NOIO);
 u8 *ivs = kmalloc(PN_MAX_ENTRIES * 16, GFP_NOIO);
 u32 iv = p->profile.iv_size, group = PN_CARRIER / iv;
 u64 unit = p->profile.sector_size;
 u64 first = hidden ? offset / PN_DATA : offset / unit / group;
 u64 last = hidden ? (offset + bytes - 1) / PN_DATA : (offset + bytes - 1) / unit / group;
 u64 index, total_groups = p->profile.sectors / group;
 u32 g = 0, count = 0, i, j, attempt;
 int r = -ENOMEM;
 if (!groups || !entries || !u || !ivs) goto done;
 if (last - first >= 2 || (hidden && (bytes != PN_DATA || offset % PN_DATA))) { r = -EINVAL; goto done; }
 for (index = first; index <= last && index < total_groups; index++) {
  struct pn_group *rec = &groups[g++];
  rec->index = index;
  r = pn_carrier(p, index, rec->old); if (r) goto done;
  if (hidden) memcpy(rec->data, data, PN_DATA);
  else {
   r = pn_record(n, index, rec->old, rec->data, false, false);
   if (r == PN_UNAVAILABLE) { rec->invalid = true; r = 0; }
   if (r) goto done;
  }
  for (j = 0; j < group; j++) {
   struct pn_entry *e = &entries[count++];
   e->sector = cpu_to_le64(index * group + j);
   memcpy(e->old, rec->old + j * iv, iv);
  }
 }
 if (!hidden) for (index = max_t(u64, offset / unit, total_groups * group);
                  index <= (offset + bytes - 1) / unit; index++) {
  struct piv_sector *s = NULL;
  struct pn_entry *e;
  if (count == PN_MAX_ENTRIES) { r = -E2BIG; goto done; }
  r = piv_load(p->cc, index, &s); if (r) goto done;
  e = &entries[count++]; e->sector = cpu_to_le64(index);
  memcpy(e->old, s->original + 4112, iv); piv_sector_free(p->cc, s);
 }
 if (!count || count > (1ULL << 32) - p->encryptions) { r = -EDQUOT; goto done; }
 /* Local checks are NOT a historical nonce-uniqueness guarantee. */
 for (attempt = 0; attempt < 16; attempt++) {
  bool collision = false;
  for (i = 0; i < g; i++) {
   r = pn_record(n, groups[i].index, groups[i].fresh, groups[i].data, true, groups[i].invalid);
   if (r) goto done;
   memcpy(ivs + i * PN_CARRIER, groups[i].fresh, PN_CARRIER);
  }
  for (i = g * group; i < count; i++) get_random_bytes(ivs + i * iv, iv);
  for (i = 0; i < count; i++) {
   for (j = 0; j < count; j++) if (!memcmp(ivs + i * iv, entries[j].old, iv)) collision = true;
   for (j = 0; j < i; j++) if (!memcmp(ivs + i * iv, ivs + j * iv, iv)) collision = true;
  }
  if (!collision) break;
 }
 if (attempt == 16) { r = -EEXIST; goto done; }
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
   r = piv_load(p->cc, sector, &s); if (r) goto done;
   memcpy(u->tuple, page_address(s->page), unit); piv_sector_free(p->cc, s);
   memcpy(u->tuple + lo - start, data + lo - offset, hi - lo);
   entries[i].primary = cpu_to_le32(1);
  }
  r = piv_update(p, NULL, u, true, primary, true); if (r) goto done;
  memcpy(entries[i].tuple, u->tuple, PIV_TUPLE_BYTES);
 }
 u->flags = PIV_APPLY_DEFER_FLUSH;
 for (i = 0; i < count; i++) {
  u->sector = le64_to_cpu(entries[i].sector);
  memcpy(u->expected_iv, entries[i].old, iv); memcpy(u->tuple, entries[i].tuple, PIV_TUPLE_BYTES);
  r = piv_update(p, NULL, u, false, le32_to_cpu(entries[i].primary), true); if (r) goto done;
  if ((i + 1) % 32 == 0) { r = blkdev_issue_flush(p->cc->dev->bdev); if (r) goto done; }
 }
 r = blkdev_issue_flush(p->cc->dev->bdev);
 if (!r) for (i = 0; i < g; i++) if (groups[i].invalid) n->invalidations++;
done:
 kvfree_sensitive(entries, PN_MAX_ENTRIES * sizeof(*entries));
 kfree_sensitive(groups); kfree_sensitive(u); kfree_sensitive(ivs);
 return r;
}

static int pn_setup(struct piv_control *p, struct file *controller, struct piv_native_setup *s)
{
 struct piv_native *n;
 u8 *zero;
 u64 i;
 u32 group = PN_CARRIER / p->profile.iv_size;
 int r;
 if (s->version != 3 || s->size != sizeof(*s) || s->generation != p->profile.generation ||
     s->context_length > 120 || !s->context_length || (s->flags & ~1U) ||
     memchr_inv(s->reserved, 0, sizeof(s->reserved))) return -EINVAL;
 if (p->native || !piv_quiesced(p) || !p->transaction || p->controller != controller || p->failed) return -EBUSY;
 if (p->profile.sectors < group || p->profile.sectors > (256ULL * 1024 * 1024) / p->profile.sector_size) return -EINVAL;
 n = kzalloc(sizeof(*n), GFP_NOIO); if (!n) return -ENOMEM;
 memcpy(n->key, s->key, 32); memcpy(n->context, s->context, s->context_length);
 n->context_length = s->context_length;
 n->hidden_bytes = (p->profile.sectors / group) * PN_DATA;
 n->record_cipher = crypto_alloc_aead("rfc7539(chacha20,poly1305)", 0, 0);
 n->hmac = crypto_alloc_shash("hmac(sha256)", 0, 0);
 if (IS_ERR(n->record_cipher) || IS_ERR(n->hmac)) { r = -ENOENT; goto bad; }
 r = crypto_aead_setauthsize(n->record_cipher, 16); if (r) goto bad;
 p->native = n;
 /* Hidden availability must not decide whether the decoy can be opened. */
 for (i = 0; i < p->profile.sectors; i++) {
  struct piv_sector *sector = NULL;
  r = piv_load(p->cc, i, &sector); if (r) goto bad;
  piv_sector_free(p->cc, sector);
 }
 if (s->flags & 1) {
  zero = kzalloc(PN_DATA, GFP_NOIO);
  if (!zero) { r = -ENOMEM; goto bad; }
  for (i = 0; i < n->hidden_bytes / PN_DATA; i++) {
   r = pn_write(p, true, i * PN_DATA, zero, PN_DATA); if (r) break;
  }
  kfree_sensitive(zero); if (r) goto bad;
 }
 r = piv_checkpoint(p->cc); if (r) goto bad;
 n->ready = true; p->transaction = false; p->controller = NULL;
 return 0;
bad:
 p->native = NULL; pn_free(n);
 return r;
}

static int pn_read(struct piv_control *p, bool hidden, u64 offset, u8 *data, u32 bytes)
{
 u64 unit = hidden ? PN_DATA : p->profile.sector_size, first = offset / unit, last = (offset + bytes - 1) / unit, i;
 u8 *record = hidden ? kmalloc(PN_CARRIER + PN_DATA, GFP_NOIO) : NULL;
 int r = 0;
 if (hidden && !record) return -ENOMEM;
 for (i = first; i <= last; i++) {
  u64 start = i * unit, lo = max(start, offset), hi = min(start + unit, offset + bytes);
  if (hidden) {
   r = pn_read_record(p, i, record, record + PN_CARRIER); if (r) break;
   memcpy(data + lo - offset, record + PN_CARRIER + lo - start, hi - lo);
  } else {
   struct piv_sector *s = NULL;
   r = piv_load(p->cc, i, &s); if (r) break;
   memcpy(data + lo - offset, page_address(s->page) + lo - start, hi - lo);
   piv_sector_free(p->cc, s);
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
	int r = -EIO;
	mutex_lock(&p->lock); noio = memalloc_noio_save();
	if (!p->live || !p->native || !p->native->ready || p->native->failed ||
	    p->blocked || p->transaction || p->failed) goto done;
	if (!bytes && (bio_op(bio) == REQ_OP_FLUSH || (bio->bi_opf & REQ_PREFLUSH))) {
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
			r = (bio->bi_opf & REQ_PREFLUSH) ? blkdev_issue_flush(p->cc->dev->bdev) : 0;
			if (!r) r = pn_write(p, w->hidden, w->offset, buffer, bytes);
		} else r = -EOPNOTSUPP;
	}
	if (r && r != PN_UNAVAILABLE) { p->failed = true; p->native->failed = true; }
done:
	kfree_sensitive(buffer); memalloc_noio_restore(noio); mutex_unlock(&p->lock);
	bio->bi_status = errno_to_blk_status(r == PN_UNAVAILABLE ? -EIO : r); bio_endio(bio);
	kref_put(&p->refs, piv_free); kfree(w);
}

static int pn_map(struct dm_target *ti, struct bio *bio)
{
	struct pn_view *v = ti->private;
	struct pn_work *w;
	if (bio_op(bio) != REQ_OP_READ && bio_op(bio) != REQ_OP_WRITE && bio_op(bio) != REQ_OP_FLUSH)
		return DM_MAPIO_KILL;
	w = kmalloc(sizeof(*w), GFP_NOWAIT | __GFP_NOWARN);
	if (!w) return DM_MAPIO_REQUEUE;
	INIT_WORK(&w->work, pn_worker); w->p = v->p; w->bio = bio; w->hidden = v->hidden;
	w->offset = dm_target_offset(ti, bio->bi_iter.bi_sector) << 9;
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
