/* SPDX-License-Identifier: GPL-2.0-only */
/* Experimental dual DM views. All data and persistence work runs on pn_wq,
 * outside map(), under the shared owner's lock and a NOIO allocation scope.
 * Recovery state MUST reside on the independent guest root filesystem.
 */
#define PN_GROUP 32
#define PN_DATA 320
#define PN_CARRIER 384
#define PN_MAX_ENTRIES 96
#define PN_LOG_MAX (512ULL * 1024 * 1024)
#define PN_FRAME_MAX (PN_MAX_ENTRIES * 4148 + 4)
#define PN_NONCES 1
#define PN_WAL 2
#define PN_DONE 3
#define PN_READY 4

struct pn_nonce { struct rb_node node; u8 iv[12]; };
struct pn_entry {
	__le64 sector;
	__le32 primary;
	u8 old[12];
	u8 tuple[4124];
} __packed;
struct pn_header {
	u8 magic[8];
	__le64 sequence;
	__le32 type, length;
	u8 salt[32], previous[32];
} __packed;
struct piv_native {
	struct file *log;
	struct crypto_aead *record_cipher, *log_cipher;
	struct crypto_shash *hmac, *sha;
	struct rb_root nonces;
	u32 nonce_count;
	u8 key[32], context[128], previous[32];
	u32 context_length;
	loff_t position;
	u64 sequence, hidden_bytes;
	struct pn_entry *pending;
	u32 pending_count;
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

static struct pn_nonce *pn_find(struct piv_native *n, const u8 iv[12])
{
	struct rb_node *at = n->nonces.rb_node;
	while (at) {
		struct pn_nonce *v = rb_entry(at, struct pn_nonce, node);
		int c = memcmp(iv, v->iv, 12);
		if (!c) return v;
		at = c < 0 ? at->rb_left : at->rb_right;
	}
	return NULL;
}

static int pn_insert(struct piv_native *n, const u8 iv[12])
{
	struct rb_node **at = &n->nonces.rb_node, *parent = NULL;
	struct pn_nonce *v;
	while (*at) {
		int c;
		parent = *at; v = rb_entry(parent, struct pn_nonce, node);
		c = memcmp(iv, v->iv, 12);
		if (!c) return -EEXIST;
		at = c < 0 ? &parent->rb_left : &parent->rb_right;
	}
	if (n->nonce_count >= (1U << 20)) return -EDQUOT;
	v = kmalloc(sizeof(*v), GFP_NOIO);
	if (!v) return -ENOMEM;
	memcpy(v->iv, iv, 12);
	rb_link_node(&v->node, parent, at); rb_insert_color(&v->node, &n->nonces);
	n->nonce_count++;
	return 0;
}

static int pn_file_io(struct file *f, void *data, size_t length, loff_t offset, bool write)
{
	size_t done = 0;
	while (done < length) {
		ssize_t r = write ? kernel_write(f, (u8 *)data + done, length - done, &offset) :
			kernel_read(f, (u8 *)data + done, length - done, &offset);
		if (r <= 0) return r < 0 ? r : -EIO;
		done += r;
	}
	return 0;
}

static int pn_log(struct piv_native *n, u32 type, const void *payload, u32 length)
{
	struct pn_header h = {};
	u8 key[32], info[160], *frame;
	size_t aad = sizeof(h) + n->context_length, total = aad + length + 16;
	int r;
	if (length > PN_FRAME_MAX || n->position + sizeof(h) + length + 16 > PN_LOG_MAX)
		return -ENOSPC;
	if (i_size_read(file_inode(n->log)) != n->position || file_inode(n->log)->i_nlink != 1)
		return -ESTALE;
	memcpy(h.magic, "PIVNLOG1", 8); h.sequence = cpu_to_le64(n->sequence);
	h.type = cpu_to_le32(type); h.length = cpu_to_le32(length);
	get_random_bytes(h.salt, 32); memcpy(h.previous, n->previous, 32);
	memcpy(info, "pivstore/native/log/v1", 21);
	memcpy(info + 21, n->context, n->context_length);
	r = pn_derive(n, h.salt, info, 21 + n->context_length, key);
	if (r) return r;
	frame = kvmalloc(total, GFP_NOIO);
	if (!frame) { memzero_explicit(key, 32); return -ENOMEM; }
	memcpy(frame, &h, sizeof(h)); memcpy(frame + sizeof(h), n->context, n->context_length);
	if (length) memcpy(frame + aad, payload, length);
	r = pn_aead(n->log_cipher, key, frame, aad, length, true);
	memzero_explicit(key, 32);
	if (!r) {
		/* Context is AAD only; persist header, ciphertext and tag. */
		memmove(frame + sizeof(h), frame + aad, length + 16);
		r = pn_file_io(n->log, frame, sizeof(h) + length + 16, n->position, true);
	}
	if (!r) r = vfs_fsync(n->log, 0);
	if (!r) r = pn_hash(n->sha, frame, sizeof(h) + length + 16, n->previous);
	if (!r) { n->position += sizeof(h) + length + 16; n->sequence++; }
	kvfree_sensitive(frame, total);
	return r;
}

static int pn_reserve(struct piv_native *n, const u8 *ivs, u32 count)
{
	u8 *payload;
	u32 i;
	int r;
	if (!count || count > 512 || n->nonce_count + count > (1U << 20)) return -EDQUOT;
	for (i = 0; i < count; i++) {
		u32 j;
		if (pn_find(n, ivs + i * 12)) return -EEXIST;
		for (j = 0; j < i; j++) if (!memcmp(ivs + i * 12, ivs + j * 12, 12)) return -EEXIST;
	}
	payload = kmalloc(4 + count * 12, GFP_NOIO);
	if (!payload) return -ENOMEM;
	put_unaligned_le32(count, payload); memcpy(payload + 4, ivs, count * 12);
	r = pn_log(n, PN_NONCES, payload, 4 + count * 12);
	if (!r) for (i = 0; i < count; i++) {
		r = pn_insert(n, ivs + i * 12); if (r) break;
	}
	kfree_sensitive(payload);
	return r;
}

static int pn_record(struct piv_native *n, u64 index, u8 carrier[384], u8 data[320], bool encrypt)
{
	u8 aad[160], key[32], *buffer;
	size_t length = n->context_length, value = index ? 320 : 8;
	int r;
	memcpy(aad, n->context, length);
	memcpy(aad + length, "/records/v2/", 12); length += 12;
	put_unaligned_le64(index, aad + length); length += 8;
	if (encrypt) get_random_bytes(carrier, 32);
	r = pn_derive(n, carrier, aad, length, key);
	if (r) return r;
	buffer = kzalloc(length + 352, GFP_NOIO);
	if (!buffer) { memzero_explicit(key, 32); return -ENOMEM; }
	memcpy(buffer, aad, length);
	if (encrypt) {
		memcpy(buffer + length, "PIVBLB01", 8);
		put_unaligned_le64(value, buffer + length + 8);
		memcpy(buffer + length + 16, data, value);
	} else memcpy(buffer + length, carrier + 32, 352);
	r = pn_aead(n->record_cipher, key, buffer, length, 336, encrypt);
	if (!r && encrypt) memcpy(carrier + 32, buffer + length, 352);
	if (!r && !encrypt) {
		if (memcmp(buffer + length, "PIVBLB01", 8) || get_unaligned_le64(buffer + length + 8) != value ||
		    (!index && memchr_inv(buffer + length + 24, 0, 312))) r = -EBADMSG;
		else memcpy(data, buffer + length + 16, value);
	}
	memzero_explicit(key, 32); kfree_sensitive(buffer);
	return r;
}

static int pn_read_record(struct piv_control *p, u64 index, u8 carrier[384], u8 data[320])
{
	u32 j;
	for (j = 0; j < PN_GROUP; j++) {
		struct piv_sector *s = NULL;
		int r = piv_load(p->cc, index * PN_GROUP + j, &s);
		if (r) return r;
		memcpy(carrier + j * 12, s->original + 4112, 12);
		piv_sector_free(p->cc, s);
	}
	return pn_record(p->native, index, carrier, data, false);
}

static int pn_validate_wal(struct piv_control *p)
{
	struct piv_native *n = p->native;
	u32 i, j;
	u64 previous = U64_MAX, groups = p->profile.sectors / 32;
	if (!n->pending_count || n->pending_count > PN_MAX_ENTRIES) return -EINVAL;
	for (i = 0; i < n->pending_count; i++) {
		struct pn_entry *e = &n->pending[i];
		u64 index = le64_to_cpu(e->sector);
		if (index >= p->profile.sectors || (i && index <= previous) ||
		    le32_to_cpu(e->primary) > 1 || !memcmp(e->old, e->tuple + 4112, 12) ||
		    !pn_find(n, e->old) || !pn_find(n, e->tuple + 4112)) return -EBADMSG;
		for (j = 0; j < i; j++) if (!memcmp(e->tuple + 4112, n->pending[j].tuple + 4112, 12)) return -EBADMSG;
		previous = index;
	}
	for (i = 0; i < n->pending_count;) {
		u64 index = le64_to_cpu(n->pending[i].sector), group = index / 32;
		if (group >= groups) {
			if (!le32_to_cpu(n->pending[i].primary)) return -EBADMSG;
			i++; continue;
		}
		if (index % 32 || n->pending_count - i < 32) return -EBADMSG;
		for (j = 0; j < 32; j++) if (le64_to_cpu(n->pending[i + j].sector) != index + j) return -EBADMSG;
		i += 32;
	}
	return 0;
}

static int pn_replay(struct piv_control *p)
{
	struct piv_native *n = p->native;
	struct piv_update *u;
	u32 i;
	int r = pn_validate_wal(p);
	u8 *record;
	if (r) return r;
	u = kzalloc(sizeof(*u), GFP_NOIO);
	record = kmalloc(384 + 320, GFP_NOIO);
	if (!u || !record) { r = -ENOMEM; goto done; }
	u->version = 1; u->size = sizeof(*u); u->generation = p->profile.generation;
	u->flags = PIV_APPLY_DEFER_FLUSH;
	for (i = 0; i < n->pending_count; i++) {
		struct pn_entry *e = &n->pending[i];
		u->sector = le64_to_cpu(e->sector); memcpy(u->expected_iv, e->old, 12);
		memcpy(u->tuple, e->tuple, 4124);
		r = piv_update(p, NULL, u, false, le32_to_cpu(e->primary), true);
		if (r) goto done;
		if ((i + 1) % 32 == 0) { r = blkdev_issue_flush(p->cc->dev->bdev); if (r) goto done; }
	}
	r = blkdev_issue_flush(p->cc->dev->bdev);
	if (r) goto done;
	for (i = 0; i < n->pending_count; i++) {
		u64 index = le64_to_cpu(n->pending[i].sector);
		if (!(index % 32) && index / 32 < p->profile.sectors / 32) {
			r = pn_read_record(p, index / 32, record, record + 384);
			if (r) goto done;
		}
	}
	r = pn_log(n, PN_DONE, NULL, 0);
	if (!r) { kvfree_sensitive(n->pending, n->pending_count * sizeof(*n->pending)); n->pending = NULL; n->pending_count = 0; }
done:
	kfree_sensitive(record); kfree_sensitive(u);
	return r;
}

static int pn_log_load(struct piv_control *p)
{
	struct piv_native *n = p->native;
	loff_t end = i_size_read(file_inode(n->log));
	int r = 0;
	if (end > PN_LOG_MAX) return -EFBIG;
	while (n->position < end) {
		struct pn_header h;
		u8 key[32], next[32], info[160], *frame;
		u32 length, type, count, i;
		size_t raw, aad, total;
		if (end - n->position < sizeof(h)) break; /* incomplete final append */
		r = pn_file_io(n->log, &h, sizeof(h), n->position, false);
		if (r) return r;
		length = le32_to_cpu(h.length); type = le32_to_cpu(h.type);
		if (memcmp(h.magic, "PIVNLOG1", 8) || le64_to_cpu(h.sequence) != n->sequence ||
		    memcmp(h.previous, n->previous, 32) || length > PN_FRAME_MAX) return -EBADMSG;
		raw = sizeof(h) + length + 16; aad = sizeof(h) + n->context_length; total = aad + length + 16;
		if (end - n->position < raw) break;
		frame = kvmalloc(total, GFP_NOIO);
		if (!frame) return -ENOMEM;
		r = pn_file_io(n->log, frame, raw, n->position, false);
		if (!r) r = pn_hash(n->sha, frame, raw, next);
		memmove(frame + aad, frame + sizeof(h), length + 16);
		memcpy(frame + sizeof(h), n->context, n->context_length);
		memcpy(info, "pivstore/native/log/v1", 21); memcpy(info + 21, n->context, n->context_length);
		if (!r) r = pn_derive(n, h.salt, info, 21 + n->context_length, key);
		if (!r) r = pn_aead(n->log_cipher, key, frame, aad, length, false);
		memzero_explicit(key, 32);
		if (r) goto frame_done;
		/* No payload is inspected before complete frame authentication. */
		switch (type) {
		case PN_NONCES:
			if (n->pending || length < 4) { r = -EBADMSG; break; }
			count = get_unaligned_le32(frame + aad);
			if (!count || count > 512 || length != 4 + count * 12) { r = -EBADMSG; break; }
			for (i = 0; i < count; i++) { r = pn_insert(n, frame + aad + 4 + i * 12); if (r) break; }
			break;
		case PN_WAL:
			if (!n->ready || n->pending || length < 4) { r = -EBADMSG; break; }
			count = get_unaligned_le32(frame + aad);
			if (!count || count > PN_MAX_ENTRIES || length != 4 + count * sizeof(struct pn_entry)) { r = -EBADMSG; break; }
			n->pending = kvmalloc(count * sizeof(struct pn_entry), GFP_NOIO);
			if (!n->pending) { r = -ENOMEM; break; }
			memcpy(n->pending, frame + aad + 4, count * sizeof(struct pn_entry));
			n->pending_count = count; r = pn_validate_wal(p);
			break;
		case PN_DONE:
			if (!n->pending || length) { r = -EBADMSG; break; }
			kvfree_sensitive(n->pending, n->pending_count * sizeof(*n->pending));
			n->pending = NULL; n->pending_count = 0;
			break;
		case PN_READY:
			if (n->ready || n->pending || length) r = -EBADMSG;
			else n->ready = true;
			break;
		default: r = -EBADMSG;
		}
frame_done:
		kvfree_sensitive(frame, total);
		if (r) return r;
		memcpy(n->previous, next, 32); n->position += raw; n->sequence++;
	}
	if (n->position != end) {
		/* No primary encryption/application may precede a successfully fsynced
		 * reservation/WAL. An incomplete last append cannot have authorized I/O.
		 * Complete but unauthentic frames are never discarded above.
		 */
		r = vfs_truncate(&n->log->f_path, n->position);
		if (!r) r = vfs_fsync(n->log, 0);
	}
	return r;
}

static void pn_free(struct piv_native *n)
{
	struct rb_node *node;
	if (!n) return;
	while ((node = rb_first(&n->nonces))) { rb_erase(node, &n->nonces); kfree_sensitive(rb_entry(node, struct pn_nonce, node)); }
	if (!IS_ERR_OR_NULL(n->record_cipher)) crypto_free_aead(n->record_cipher);
	if (!IS_ERR_OR_NULL(n->log_cipher)) crypto_free_aead(n->log_cipher);
	if (!IS_ERR_OR_NULL(n->hmac)) crypto_free_shash(n->hmac);
	if (!IS_ERR_OR_NULL(n->sha)) crypto_free_shash(n->sha);
	if (!IS_ERR_OR_NULL(n->log)) filp_close(n->log, NULL);
	kvfree_sensitive(n->pending, n->pending_count * sizeof(*n->pending));
	kfree_sensitive(n);
}

static int pn_compare_iv(const void *a, const void *b) { return memcmp(a, b, 12); }
static int pn_verify(struct piv_control *p)
{
	struct piv_native *n = p->native;
	u8 *ivs = kvmalloc(p->profile.sectors * 12, GFP_NOIO), *record;
	u64 i, records = p->profile.sectors / 32;
	int r = 0;
	record = kmalloc(704, GFP_NOIO);
	if (!ivs || !record) { r = -ENOMEM; goto done; }
	for (i = 0; i < p->profile.sectors; i++) {
		struct piv_sector *s = NULL;
		r = piv_load(p->cc, i, &s); if (r) goto done;
		memcpy(ivs + i * 12, s->original + 4112, 12); piv_sector_free(p->cc, s);
		if (!pn_find(n, ivs + i * 12)) { r = -ESTALE; goto done; }
	}
	sort(ivs, p->profile.sectors, 12, pn_compare_iv, NULL);
	for (i = 1; i < p->profile.sectors; i++) if (!memcmp(ivs + i * 12, ivs + (i - 1) * 12, 12)) { r = -EEXIST; goto done; }
	for (i = 0; i < records; i++) {
		u64 start = i ? (i - 1) * 320 : 0;
		r = pn_read_record(p, i, record, record + 384); if (r) goto done;
		if (!i) { if (get_unaligned_le64(record + 384) != n->hidden_bytes) { r = -EBADMSG; goto done; } }
		else if (start + 320 > n->hidden_bytes) {
			u32 used = start >= n->hidden_bytes ? 0 : n->hidden_bytes - start;
			if (memchr_inv(record + 384 + used, 0, 320 - used)) { r = -EBADMSG; goto done; }
		}
	}
done:
	kvfree_sensitive(ivs, p->profile.sectors * 12); kfree_sensitive(record);
	return r;
}

static int pn_setup(struct piv_control *p, struct file *controller, struct piv_native_setup *s, const u8 *seeds)
{
	struct piv_native *n;
	u8 *batch = NULL;
	u32 i, count = 0;
	int r;
	if (s->version != 1 || s->size != sizeof(*s) || s->generation != p->profile.generation ||
	    s->context_length > 120 || !s->context_length || s->nonce_count > (1U << 20) ||
	    s->path[0] != '/' || !memchr(s->path, 0, sizeof(s->path)) ||
	    memchr_inv(s->reserved, 0, sizeof(s->reserved))) return -EINVAL;
	if (p->native || !piv_quiesced(p) || !p->transaction || p->controller != controller || p->failed) return -EBUSY;
	if (p->profile.sectors < 64 || p->profile.sectors > 65536) return -EINVAL;
	n = kzalloc(sizeof(*n), GFP_NOIO); if (!n) return -ENOMEM;
	batch = kmalloc(512 * 12, GFP_NOIO);
	if (!batch) { kfree(n); return -ENOMEM; }
	n->nonces = RB_ROOT; memcpy(n->key, s->key, 32);
	memcpy(n->context, s->context, s->context_length); n->context_length = s->context_length;
	n->hidden_bytes = (((p->profile.sectors / 32 - 1) * 320) / 512) * 512;
	n->record_cipher = crypto_alloc_aead("rfc7539(chacha20,poly1305)", 0, 0);
	n->log_cipher = crypto_alloc_aead("gcm(aes)", 0, 0);
	n->hmac = crypto_alloc_shash("hmac(sha256)", 0, 0);
	n->sha = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(n->record_cipher) || IS_ERR(n->log_cipher) || IS_ERR(n->hmac) || IS_ERR(n->sha)) { r = -ENOENT; goto bad; }
	r = crypto_aead_setauthsize(n->record_cipher, 16); if (r) goto bad;
	r = crypto_aead_setauthsize(n->log_cipher, 16); if (r) goto bad;
	n->log = filp_open(s->path, O_RDWR | O_NOFOLLOW | O_LARGEFILE, 0);
	if (IS_ERR(n->log)) { r = PTR_ERR(n->log); goto bad; }
	if (!S_ISREG(file_inode(n->log)->i_mode) || file_inode(n->log)->i_nlink != 1 ||
	    (file_inode(n->log)->i_mode & 077) || !uid_eq(file_inode(n->log)->i_uid, GLOBAL_ROOT_UID) ||
	    file_inode(n->log)->i_sb->s_magic != EXT4_SUPER_MAGIC) { r = -EPERM; goto bad; }
	p->native = n;
	r = pn_log_load(p); if (r) goto bad;
	if (!n->ready) {
		if (!s->nonce_count) { r = -ENODATA; goto bad; }
		for (i = 0; i < s->nonce_count; i++) {
			if (pn_find(n, seeds + i * 12)) continue; /* interrupted seed import */
			memcpy(batch + count++ * 12, seeds + i * 12, 12);
			if (count == 512) { r = pn_reserve(n, batch, count); if (r) goto bad; count = 0; }
		}
		if (count) { r = pn_reserve(n, batch, count); if (r) goto bad; }
		r = pn_verify(p); if (r) goto bad;
		r = pn_log(n, PN_READY, NULL, 0); if (r) goto bad;
		n->ready = true;
	} else if (n->pending) { r = pn_replay(p); if (r) goto bad; }
	r = pn_verify(p); if (r) goto bad;
	r = piv_checkpoint(p->cc); if (r) goto bad;
	p->transaction = false; p->controller = NULL;
	kfree_sensitive(batch);
	return 0;
bad:
	kfree_sensitive(batch);
	p->native = NULL; pn_free(n);
	return r;
}

struct pn_group { u64 index; u8 data[320], old[384], fresh[384]; };

static int pn_write(struct piv_control *p, bool hidden, u64 offset, const u8 *data, u32 bytes)
{
	struct piv_native *n = p->native;
	struct pn_group *groups = kcalloc(3, sizeof(*groups), GFP_NOIO);
	struct pn_entry *entries = kvcalloc(PN_MAX_ENTRIES, sizeof(*entries), GFP_NOIO);
	struct piv_update *u = kzalloc(sizeof(*u), GFP_NOIO);
	u8 ivs[PN_MAX_ENTRIES * 12], *payload = NULL;
	u64 first = hidden ? 1 + offset / 320 : offset / 4096 / 32;
	u64 last = hidden ? 1 + (offset + bytes - 1) / 320 : (offset + bytes - 1) / 4096 / 32;
	u64 index, total_groups = p->profile.sectors / 32;
	u32 g = 0, count = 0, i, j, attempt;
	int r = -ENOMEM;
	if (!groups || !entries || !u) goto done;
	if (last - first >= 3) { r = -E2BIG; goto done; }
	for (index = first; index <= last && index < total_groups; index++) {
		struct pn_group *rec = &groups[g++];
		rec->index = index;
		r = pn_read_record(p, index, rec->old, rec->data); if (r) goto done;
		if (hidden) {
			u64 start = (index - 1) * 320, lo = max(start, offset), hi = min(start + 320, offset + bytes);
			memcpy(rec->data + lo - start, data + lo - offset, hi - lo);
		}
		for (j = 0; j < 32; j++) {
			struct pn_entry *e = &entries[count++];
			e->sector = cpu_to_le64(index * 32 + j); memcpy(e->old, rec->old + j * 12, 12);
		}
	}
	if (!hidden) for (index = max_t(u64, offset / 4096, total_groups * 32);
			 index <= (offset + bytes - 1) / 4096; index++) {
		struct piv_sector *s = NULL;
		struct pn_entry *e;
		if (count == PN_MAX_ENTRIES) { r = -E2BIG; goto done; }
		r = piv_load(p->cc, index, &s); if (r) goto done;
		e = &entries[count++]; e->sector = cpu_to_le64(index);
		memcpy(e->old, s->original + 4112, 12); piv_sector_free(p->cc, s);
	}
	if (!count || n->nonce_count + count > (1U << 20)) { r = -EDQUOT; goto done; }
	if (n->position + 3 * (sizeof(struct pn_header) + 16) + 8 + count * (12 + sizeof(*entries)) > PN_LOG_MAX) {
		r = -ENOSPC; goto done;
	}
	for (attempt = 0; attempt < 16; attempt++) {
		bool collision = false;
		for (i = 0; i < g; i++) {
			r = pn_record(n, groups[i].index, groups[i].fresh, groups[i].data, true); if (r) goto done;
			for (j = 0; j < 32; j++) memcpy(ivs + (i * 32 + j) * 12, groups[i].fresh + j * 12, 12);
		}
		for (i = g * 32; i < count; i++) get_random_bytes(ivs + i * 12, 12);
		for (i = 0; i < count; i++) {
			if (pn_find(n, ivs + i * 12)) collision = true;
			for (j = 0; j < i; j++) if (!memcmp(ivs + i * 12, ivs + j * 12, 12)) collision = true;
		}
		if (!collision) break;
	}
	if (attempt == 16) { r = -EEXIST; goto done; }
	r = pn_reserve(n, ivs, count); if (r) goto done; /* durable BEFORE primary encryption */
	u->version = 1; u->size = sizeof(*u); u->generation = p->profile.generation;
	for (i = 0; i < count; i++) {
		u64 sector = le64_to_cpu(entries[i].sector), start = sector * 4096;
		bool primary = !hidden && start < offset + bytes && start + 4096 > offset;
		memset(u->tuple, 0, sizeof(u->tuple)); u->sector = sector;
		memcpy(u->expected_iv, entries[i].old, 12); memcpy(u->tuple + 4112, ivs + i * 12, 12);
		if (primary) {
			struct piv_sector *s = NULL;
			u64 lo = max(start, offset), hi = min(start + 4096, offset + bytes);
			r = piv_load(p->cc, sector, &s); if (r) goto done;
			memcpy(u->tuple, page_address(s->page), 4096); piv_sector_free(p->cc, s);
			memcpy(u->tuple + lo - start, data + lo - offset, hi - lo);
			entries[i].primary = cpu_to_le32(1);
		}
		r = piv_update(p, NULL, u, true, primary, true); if (r) goto done;
		memcpy(entries[i].tuple, u->tuple, 4124);
	}
	payload = kvmalloc(4 + count * sizeof(*entries), GFP_NOIO);
	if (!payload) { r = -ENOMEM; goto done; }
	put_unaligned_le32(count, payload); memcpy(payload + 4, entries, count * sizeof(*entries));
	r = pn_log(n, PN_WAL, payload, 4 + count * sizeof(*entries)); if (r) goto done;
	n->pending = entries; n->pending_count = count; entries = NULL;
	r = pn_replay(p);
done:
	kvfree_sensitive(payload, 4 + count * sizeof(struct pn_entry));
	kvfree_sensitive(entries, PN_MAX_ENTRIES * sizeof(*entries));
	kfree_sensitive(groups); kfree_sensitive(u); memzero_explicit(ivs, sizeof(ivs));
	return r;
}

static int pn_read(struct piv_control *p, bool hidden, u64 offset, u8 *data, u32 bytes)
{
	u64 unit = hidden ? 320 : 4096, first = offset / unit, last = (offset + bytes - 1) / unit, i;
	u8 *record = hidden ? kmalloc(704, GFP_NOIO) : NULL;
	int r = 0;
	if (hidden && !record) return -ENOMEM;
	for (i = first; i <= last; i++) {
		u64 start = i * unit, lo = max(start, offset), hi = min(start + unit, offset + bytes);
		if (hidden) {
			r = pn_read_record(p, i + 1, record, record + 384); if (r) break;
			memcpy(data + lo - offset, record + 384 + lo - start, hi - lo);
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
		if (!r) r = vfs_fsync(p->native->log, 0);
	} else {
		u64 limit = w->hidden ? p->native->hidden_bytes : p->profile.sectors * 4096;
		if (!bytes || bytes > (w->hidden ? 512 : 4096) || (w->offset & 511) ||
		    (bytes & 511) || w->offset > limit || bytes > limit - w->offset) { r = -EINVAL; goto done; }
		buffer = kmalloc(bytes, GFP_NOIO);
		if (!buffer) { r = -ENOMEM; goto done; }
		if (bio_op(bio) == REQ_OP_READ) {
			r = pn_read(p, w->hidden, w->offset, buffer, bytes);
			if (!r) pn_copy_bio(bio, buffer, true);
		} else if (bio_op(bio) == REQ_OP_WRITE) {
			pn_copy_bio(bio, buffer, false);
			r = pn_write(p, w->hidden, w->offset, buffer, bytes);
		} else r = -EOPNOTSUPP;
	}
	if (r) { p->failed = true; p->native->failed = true; }
done:
	kfree_sensitive(buffer); memalloc_noio_restore(noio); mutex_unlock(&p->lock);
	bio->bi_status = errno_to_blk_status(r); bio_endio(bio);
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
	    ti->begin || ti->len != (v->hidden ? found->native->hidden_bytes / 512 : found->profile.sectors * 8) ||
	    (found->native->views & (v->hidden ? 2 : 1))) r = -EINVAL;
	else { found->native->views |= v->hidden ? 2 : 1; r = 0; }
	mutex_unlock(&found->lock);
	if (r) { dm_put_device(ti, v->owner); goto free_ref; }
	ti->private = v; ti->num_flush_bios = 1;
	r = dm_set_target_max_io_len(ti, v->hidden ? 1 : 8);
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
	return fn(ti, v->owner, 0, v->p->profile.sectors * 8, data);
}
static void pn_hints(struct dm_target *ti, struct queue_limits *limits)
{
	/* This target performs its own authenticated 4KiB RMW and may expose 512B. */
	limits->logical_block_size = 512; limits->physical_block_size = 4096;
	limits->io_min = 4096; limits->dma_alignment = 511;
}
static void pn_status(struct dm_target *ti, status_type_t type, unsigned int flags, char *result, unsigned int maxlen)
{
	struct pn_view *v = ti->private;
	unsigned int sz = 0;
	DMEMIT("%s %llu %s", v->owner->name, (unsigned long long)v->p->profile.generation, v->hidden ? "hidden" : "decoy");
}
static struct target_type piv_view_target = {
	.name = "piv-view", .version = {0, 1, 0}, .module = THIS_MODULE,
	.ctr = pn_ctr, .dtr = pn_dtr, .map = pn_map, .iterate_devices = pn_iterate,
	.io_hints = pn_hints, .status = pn_status,
};
