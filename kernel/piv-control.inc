#include <crypto/hash.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <linux/highmem.h>
#include <linux/sort.h>
#include <linux/vmalloc.h>
#include <linux/unaligned.h>
#include <linux/rbtree.h>
#include <linux/sched/signal.h>
#include <linux/rwsem.h>
#include <linux/wait.h>
/* SPDX-License-Identifier: GPL-2.0-only */
/* Included after native AEAD helpers. cc is borrowed only while lock is held.
 * misc_open serializes our open callback with misc_deregister via misc_mtx.
 * A registration reference survives deregistration; each open takes its own.
 * Open fds pin THIS_MODULE and remain valid (ENODEV) after target destruction.
 */
struct piv_native;
static LIST_HEAD(piv_controls);
static DEFINE_MUTEX(piv_controls_lock);
static atomic64_t piv_generation = ATOMIC64_INIT(0);
struct piv_control {
	struct list_head list;
	struct piv_native *native;
	struct miscdevice misc;
	struct kref refs;
	struct mutex lock;
	/* Public-view I/O runs concurrently under @io (shared). Owner state that
	 * workers read (live, blocked, cc, native and its keyslot/directory
	 * state) changes only under @lock plus @io exclusive, which also drains
	 * in-flight requests. Exception: while no view exists and the owner is
	 * blocked (suspended), no worker can reach that state, so setup and
	 * BEGIN/END change native/transaction under @lock alone. Lock order:
	 * @lock, then @io.
	 */
	struct rw_semaphore io;
	/* View requests and setup's record work: per owner, so a stalled lower
	 * device occupies only its own owner's workers (PN_MAX_ACTIVE).
	 */
	struct workqueue_struct *wq;
	struct work_struct free_work;
	/* Flush tracking (piv_flush): lower write batches completed, and the
	 * value sampled when the newest successful flush started. A write counted
	 * at or below @flushed is durable.
	 */
	atomic64_t writes_done;
	atomic64_t flushed;
	/* Range locks over primary sectors (piv_range_lock), arrival order. */
	spinlock_t ranges_lock;
	struct list_head ranges;
	wait_queue_head_t ranges_wait;
	bool live;
	bool blocked;
	bool activated;
	bool resuming;
	bool transaction;
	bool failed;	/* sticky; workers set it with WRITE_ONCE */
	atomic64_t encryptions;
	struct file *controller;
	struct piv_crypt *cc;
	struct piv_query profile;
	struct piv_devices devices;
	char name[40];
};

/* The last reference may drop inside a work item of p->wq itself (pn_worker),
 * which cannot destroy its own workqueue: defer to kpiv_io. Module exit
 * drains kpiv_io.
 */
static void piv_free_work(struct work_struct *work)
{
	struct piv_control *p = container_of(work, struct piv_control, free_work);
	if (p->wq)
		destroy_workqueue(p->wq);
	kfree(p);
}

static void piv_free(struct kref *ref)
{
	struct piv_control *p = container_of(ref, struct piv_control, refs);
	queue_work(piv_io_wq, &p->free_work);
}

static int piv_open(struct inode *inode, struct file *file)
{
	struct piv_control *p = container_of(file->private_data,
					   struct piv_control, misc);
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	kref_get(&p->refs);
	file->private_data = p;
	return 0;
}

/* A controller that exits inside BEGIN/END leaves the transaction set:
 * resume stays refused (-EBUSY) until another controller BEGINs and ENDs it
 * or the owner is removed (pivsetup's cleanup removes it). A half-finished
 * setup must not silently become resumable.
 */
static int piv_release(struct inode *inode, struct file *file)
{
	struct piv_control *p = file->private_data;
	mutex_lock(&p->lock);
	if (p->controller == file)
		p->controller = NULL;
	mutex_unlock(&p->lock);
	kref_put(&p->refs, piv_free);
	return 0;
}

#define PIV_MAX_TAG 64

/* Range locks over primary sector indices serialize every request that
 * rewrites sectors with every other request touching them: decoy writes
 * (their sectors), hidden writes (the block's whole record group, both slots
 * with A/B) and hidden reads (shared, so a read never collects a half-written
 * record). Decoy reads take none: dm-integrity keeps each sector whole and
 * they publish per-sector authenticated data. Entries queue in arrival order
 * and wait only for earlier overlapping entries that conflict (at least one
 * exclusive), so there is no starvation; a request holds at most one range
 * and every entry it waits for belongs to a running request, so there is no
 * deadlock.
 */
struct piv_range {
	struct list_head list;
	u64 first, end;
	bool exclusive;
};

static bool piv_range_ready(struct piv_control *p, struct piv_range *r)
{
	struct piv_range *e;
	bool ready = true;
	spin_lock(&p->ranges_lock);
	list_for_each_entry(e, &p->ranges, list) {
		if (e == r)
			break;
		if (e->first < r->end && r->first < e->end && (e->exclusive || r->exclusive)) {
			ready = false;
			break;
		}
	}
	spin_unlock(&p->ranges_lock);
	return ready;
}

static void piv_range_lock(struct piv_control *p, struct piv_range *r, u64 first, u64 count, bool exclusive)
{
	r->first = first;
	r->end = first + count;
	r->exclusive = exclusive;
	spin_lock(&p->ranges_lock);
	list_add_tail(&r->list, &p->ranges);
	spin_unlock(&p->ranges_lock);
	/* Uninterruptible: a stalled lower device shows waiters (and an owner
	 * presuspend waiting for @io) as hung tasks, not as a deadlock.
	 */
	wait_event(p->ranges_wait, piv_range_ready(p, r));
}

static void piv_range_unlock(struct piv_control *p, struct piv_range *r)
{
	spin_lock(&p->ranges_lock);
	list_del(&r->list);
	spin_unlock(&p->ranges_lock);
	wake_up_all(&p->ranges_wait);
}

/* Volatile per-owner diagnostic cap on primary encryptions. It does not
 * enforce the per-key lifetime budget (docs/security-review.md); 2^40 matches
 * that guidance's example budget and admits initialization far beyond the
 * former 2^32 (about 2 TiB at 512-byte sectors).
 */
#define PIV_ENCRYPTION_CAP (1ULL << 40)

/* Reserve @count encryptions atomically before performing them. */
static int piv_reserve(struct piv_control *p, u32 count)
{
	s64 old = atomic64_read(&p->encryptions);
	do {
		if (count > PIV_ENCRYPTION_CAP - (u64)old)
			return -EDQUOT;
	} while (!atomic64_try_cmpxchg(&p->encryptions, &old, old + count));
	return 0;
}

static int piv_identity(struct piv_control *p, u32 version, u32 size,
			u64 generation, u64 sector, unsigned int expected_size)
{
	if (version != PIV_CONTROL_VERSION || size != expected_size)
		return -EINVAL;
	if (generation != p->profile.generation)
		return -ESTALE;
	if (sector >= p->profile.sectors)
		return -ERANGE;
	if (!p->activated || !test_bit(PIV_KEY_VALID, &p->cc->flags))
		return -EBUSY;
	return 0;
}

static bool piv_quiesced(struct piv_control *p)
{
	return p->blocked && !p->resuming &&
		test_bit(PIV_SUSPENDED, &p->cc->flags);
}

/* Rewrites (decoy writes, hidden records, keyslots; docs/native-blocks.md).
 * A request's primary sectors are read and authenticated once, re-encrypted in
 * place under fresh IVs and written back as a few multi-sector bios that carry
 * their integrity tuples; the request waits once for all of them (and flushes
 * only where its caller requires durability: FUA, keyslots, the directory).
 * Every step that can fail without touching storage (lower reads,
 * authentication, allocation, encryption) finishes for the whole request before
 * the first lower write, so such errors fail only that request.
 *
 * Nothing re-reads the sectors between authentication and the write. The
 * former per-sector re-read with an expected-IV (ESTALE) check dates from the
 * userspace PREPARE/APPLY interface, where another caller could change a
 * sector between the two ioctls. Every mutation now runs inside the kernel
 * owner: view requests hold an exclusive range lock over the sectors they
 * rewrite (piv_range_lock), control calls hold p->io exclusive, and the private
 * owner mapping kills all bios while native ownership is active, so nothing
 * coordinated can change a sector in between; an uncoordinated writer of the
 * lower device was never excluded by a re-read either (it can still race the
 * write). Freshly produced ciphertext is not decrypted again: that check
 * guarded userspace-supplied tuples; here the same piv_aead() call that every
 * read uses produces it, and later reads authenticate every sector anyway.
 *
 * Bio size: at most PIV_IO_BYTES of data and one page of tuples per bio,
 * rounded to whole pages, so the tuple buffer of a bio is one order-0 slab
 * object (32 sectors per bio at 4096-byte sectors, 80-128 at 512).
 */
#define PIV_BATCH_MAX 1024	/* sectors per request; >= PN_MAX_GROUP */
struct piv_batch {
	struct piv_control *p;
	u64 index;		/* first primary sector */
	u32 count, per_bio, bios, npages;
	struct page **pages;	/* count * sector_size bytes, sectors packed */
	u8 **meta;		/* per bio: per_bio tuples (tag || IV) */
	u8 *olds;		/* rewrites only: 16 bytes per sector, the stored IV */
	unsigned long *replace;	/* rewrites only: failed authentication; fully overwritten */
	s64 seq;		/* after a write: the writes_done value counting it */
	/* One AEAD request and buffer set reused for every sector (piv_aead). */
	struct aead_request *req;
	struct piv_aead_buffers *aead;
};

static u8 *piv_batch_tuple(struct piv_batch *b, u32 i)
{
	return b->meta[i / b->per_bio] + (i % b->per_bio) * b->p->cc->tuple_size;
}

static void piv_batch_free(struct piv_batch *b)
{
	u32 i;
	if (!b)
		return;
	for (i = 0; b->pages && i < b->npages; i++)
		if (b->pages[i]) {
			memzero_explicit(page_address(b->pages[i]), PAGE_SIZE);
			__free_page(b->pages[i]);
		}
	for (i = 0; b->meta && i < b->bios; i++)
		kfree_sensitive(b->meta[i]);
	kvfree(b->pages);
	kfree(b->meta);
	if (b->olds)
		kvfree_sensitive(b->olds, b->count * 16);
	bitmap_free(b->replace);
	aead_request_free(b->req);
	kfree_sensitive(b->aead);
	kfree(b);
}

/* @rewrite: also allocate the stored-IV and replacement bookkeeping. */
static int piv_batch_alloc(struct piv_control *p, u64 index, u32 count, bool rewrite, struct piv_batch **out)
{
	struct piv_crypt *cc = p->cc;
	struct piv_batch *b;
	u32 i, per_page = PAGE_SIZE / cc->sector_size;
	if (!count || count > PIV_BATCH_MAX || index >= p->profile.sectors ||
	    count > p->profile.sectors - index || cc->tuple_size > PAGE_SIZE / per_page)
		return -EINVAL;
	b = kzalloc(sizeof(*b), GFP_NOIO);
	if (!b)
		return -ENOMEM;
	b->p = p;
	b->index = index;
	b->count = count;
	b->per_bio = min_t(u32, PIV_IO_BYTES / cc->sector_size, PAGE_SIZE / cc->tuple_size);
	b->per_bio -= b->per_bio % per_page;
	b->bios = DIV_ROUND_UP(count, b->per_bio);
	b->npages = DIV_ROUND_UP(count, per_page);
	b->pages = kvcalloc(b->npages, sizeof(*b->pages), GFP_NOIO);
	b->meta = kcalloc(b->bios, sizeof(*b->meta), GFP_NOIO);
	b->req = aead_request_alloc(cc->tfm, GFP_NOIO);
	b->aead = kzalloc(sizeof(*b->aead), GFP_NOIO);
	if (!b->pages || !b->meta || !b->req || !b->aead)
		goto bad;
	if (rewrite) {
		b->olds = kvmalloc(count * 16, GFP_NOIO);
		b->replace = bitmap_zalloc(count, GFP_NOIO);
		if (!b->olds || !b->replace)
			goto bad;
	}
	for (i = 0; i < b->npages; i++) {
		b->pages[i] = alloc_page(GFP_NOIO);
		if (!b->pages[i])
			goto bad;
	}
	for (i = 0; i < b->bios; i++) {
		b->meta[i] = kzalloc(b->per_bio * cc->tuple_size, GFP_NOIO);
		if (!b->meta[i])
			goto bad;
	}
	*out = b;
	return 0;
bad:
	piv_batch_free(b);
	return -ENOMEM;
}

/* Sector @i of the batch in place: encrypt under @iv, or authenticate and
 * decrypt with @iv NULL.
 */
static int piv_batch_crypt(struct piv_batch *b, u32 i, const u8 *iv)
{
	struct piv_crypt *cc = b->p->cc;
	u64 at = (u64)i * cc->sector_size;
	return piv_aead(cc, b->req, b->aead, (b->index + i) << cc->sector_shift, b->pages[at >> PAGE_SHIFT],
			at & ~PAGE_MASK, piv_batch_tuple(b, i), iv, iv != NULL);
}

struct piv_batch_wait {
	atomic_t pending;
	atomic_t error;
	struct completion done;
};

static void piv_batch_endio(struct bio *bio)
{
	struct piv_batch_wait *w = bio->bi_private;
	if (bio->bi_status)
		atomic_cmpxchg(&w->error, 0, blk_status_to_errno(bio->bi_status));
	bio_put(bio);
	if (atomic_dec_and_test(&w->pending))
		complete(&w->done);
}

/* Build every bio of the batch, then submit them all and wait once. Nothing is
 * submitted if building fails. With @mutated (writes), *@mutated is set before
 * the first submission. A completed write batch (failed or not) is counted in
 * writes_done (b->seq) for flush tracking. noinline: the profile suite counts
 * submissions here.
 */
static noinline int piv_batch_submit(struct piv_batch *b, blk_opf_t op, bool *mutated)
{
	struct piv_crypt *cc = b->p->cc;
	struct piv_batch_wait wait;
	struct bio **bios;
	u32 c, per_page = PAGE_SIZE / cc->sector_size;
	int r = 0;
	bios = kcalloc(b->bios, sizeof(*bios), GFP_NOIO);
	if (!bios)
		return -ENOMEM;
	atomic_set(&wait.pending, b->bios + 1);
	atomic_set(&wait.error, 0);
	init_completion(&wait.done);
	for (c = 0; c < b->bios && !r; c++) {
		u32 first = c * b->per_bio, n = min(b->per_bio, b->count - first), j;
		u32 bytes = n * cc->sector_size, page = first / per_page;
		sector_t sector = (b->index + first) << cc->sector_shift;
		bios[c] = bio_alloc(cc->dev->bdev, DIV_ROUND_UP(bytes, PAGE_SIZE), op, GFP_NOIO);
		if (!bios[c]) {
			r = -ENOMEM;
			break;
		}
		bios[c]->bi_iter.bi_sector = sector;
		bios[c]->bi_end_io = piv_batch_endio;
		bios[c]->bi_private = &wait;
		for (j = 0; j * PAGE_SIZE < bytes && !r; j++) {
			u32 length = min_t(u32, PAGE_SIZE, bytes - j * PAGE_SIZE);
			if (bio_add_page(bios[c], b->pages[page + j], length, 0) != length)
				r = -ENOMEM;
		}
		if (!r)
			r = piv_integrity_alloc(cc, bios[c], sector, b->meta[c]);
	}
	if (r) {
		for (c = 0; c < b->bios; c++)
			if (bios[c])
				bio_put(bios[c]);
		kfree(bios);
		return r;
	}
	if (mutated)
		*mutated = true;
	for (c = 0; c < b->bios; c++)
		submit_bio(bios[c]);
	if (!atomic_dec_and_test(&wait.pending))
		wait_for_completion_io(&wait.done);
	kfree(bios);
	if (op_is_write(op))
		b->seq = atomic64_inc_return(&b->p->writes_done);
	return atomic_read(&wait.error);
}

/* Flush the lower device. On success every write batch counted before the
 * flush started is durable: @flushed advances to that count. noinline: the v5
 * suite counts calls (A/B flush skipping).
 */
static noinline int piv_flush(struct piv_control *p)
{
	s64 seq = atomic64_read(&p->writes_done), old;
	int r = blkdev_issue_flush(p->cc->dev->bdev);
	if (r)
		return r;
	old = atomic64_read(&p->flushed);
	while (old < seq && !atomic64_try_cmpxchg(&p->flushed, &old, seq))
		;
	return 0;
}

/* Read and authenticate @count primary sectors from @index for a rewrite.
 * Every sector must authenticate, except one failing authentication that the
 * decoy request [@offset, @offset + @bytes) covers entirely (@bytes == 0:
 * none): it is marked in -> replace and only its raw stored IV is kept (user
 * decision 2026-10-21). -> olds receives every stored IV. noinline: counted by
 * the profile suite.
 */
static noinline int piv_batch_read(struct piv_control *p, u64 index, u32 count, u64 offset, u32 bytes,
				   struct piv_batch **out)
{
	struct piv_crypt *cc = p->cc;
	struct piv_batch *b = NULL;
	u64 unit = cc->sector_size;
	u32 i;
	int r = piv_batch_alloc(p, index, count, true, &b);
	if (r)
		return r;
	r = piv_batch_submit(b, REQ_OP_READ, NULL);
	for (i = 0; !r && i < count; i++) {
		u64 start = (index + i) * unit;
		memcpy(b->olds + i * 16, piv_batch_tuple(b, i) + cc->integrity_tag_size, 16);
		r = piv_batch_crypt(b, i, NULL);
		if (r == -EBADMSG && bytes && start >= offset && start + unit <= offset + bytes) {
			__set_bit(i, b->replace);
			r = 0;
		}
	}
	if (r) {
		piv_batch_free(b);
		return r;
	}
	*out = b;
	return 0;
}

/* Destination of authenticated plaintext: a linear buffer, or the remaining
 * data of a bio (copied straight into its pages, no intermediate buffer).
 */
struct piv_out {
	u8 *data;
	struct bio *bio;
	struct bvec_iter iter;
};

static void piv_out_copy(struct piv_out *o, const u8 *src, u32 length)
{
	if (o->data) {
		memcpy(o->data, src, length);
		o->data += length;
		return;
	}
	while (length) {
		struct bio_vec v = bio_iter_iovec(o->bio, o->iter);
		u32 n = min(length, v.bv_len);
		memcpy_to_page(v.bv_page, v.bv_offset, src, n);
		bio_advance_iter_single(o->bio, &o->iter, n);
		src += n;
		length -= n;
	}
}

/* Bounded authenticated reads (setup scans, decoy reads, hidden carrier
 * collection, owner reads, the checkpoint): at most PIV_READ_SECTORS sectors
 * per call, read as one batch of multi-sector bios in flight together. No
 * cache: every call fetches current tuples through the same integrity device.
 */
#define PIV_READ_SECTORS PIV_BATCH_MAX

/* Read @count primary sectors from @index and authenticate every one with its
 * own address/IV AAD before publishing anything: plaintext bytes [@skip,
 * @skip + @length) of the range into @out and/or stored IVs into @ivs, only
 * after all sectors verify. With @bad (tolerant IV collection for SIV-checked
 * decoding; @out must be NULL), a sector failing authentication sets bit
 * @bad_at + i and contributes its raw stored IV. noinline: the profile and
 * cancel suites count calls.
 */
static noinline int piv_read_range(struct piv_control *p, u64 index, u32 count, struct piv_out *out,
				   u64 skip, u64 length, u8 *ivs, unsigned long *bad, u32 bad_at)
{
	struct piv_crypt *cc = p->cc;
	struct piv_batch *b = NULL;
	u32 i;
	int r;
	if (!count || count > PIV_READ_SECTORS || (bad && out) ||
	    (out && (skip > (u64)count * cc->sector_size || length > (u64)count * cc->sector_size - skip)))
		return -EINVAL;
	r = piv_batch_alloc(p, index, count, false, &b);
	if (r)
		return r;
	r = piv_batch_submit(b, REQ_OP_READ, NULL);
	for (i = 0; !r && i < count; i++) {
		r = piv_batch_crypt(b, i, NULL);
		if (r == -EBADMSG && bad) {
			__set_bit(bad_at + i, bad);
			r = 0;
		}
	}
	while (!r && out && length) {
		u32 n = min_t(u64, length, PAGE_SIZE - (skip & ~PAGE_MASK));
		piv_out_copy(out, page_address(b->pages[skip >> PAGE_SHIFT]) + (skip & ~PAGE_MASK), n);
		skip += n;
		length -= n;
	}
	for (i = 0; !r && ivs && i < count; i++)
		memcpy(ivs + i * cc->iv_size, piv_batch_tuple(b, i) + cc->integrity_tag_size, cc->iv_size);
	piv_batch_free(b);
	return r;
}

/* Copy request bytes [@offset, @offset + @bytes) (primary byte offsets inside
 * the batch) into the authenticated plaintext.
 */
static void piv_batch_merge(struct piv_batch *b, u64 offset, const u8 *data, u32 bytes)
{
	u64 at = offset - b->index * b->p->cc->sector_size;
	while (bytes) {
		u32 length = min_t(u64, bytes, PAGE_SIZE - (at & ~PAGE_MASK));
		memcpy(page_address(b->pages[at >> PAGE_SHIFT]) + (at & ~PAGE_MASK), data, length);
		data += length;
		at += length;
		bytes -= length;
	}
}

/* Encrypt every sector in place under @ivs (16 bytes each, all different from
 * the stored ones), write the batch and, with @flush, flush the lower device.
 * Encryptions are reserved (counted) before encrypting, even if the write
 * later fails. *@mutated is set once writing begins; earlier failures changed
 * nothing. A request that already sees the owner fail-stopped (by a
 * concurrent request) writes nothing; one stopped after the last check below
 * may still write, and its caller then reports EIO (pn_worker).
 */
static int piv_batch_write(struct piv_batch *b, const u8 *ivs, bool flush, bool *mutated)
{
	struct piv_control *p = b->p;
	u32 i;
	int r;
	if (READ_ONCE(p->failed))
		return -EIO;
	for (i = 0; i < b->count; i++)
		if (!memcmp(ivs + i * 16, b->olds + i * 16, 16))
			return -EINVAL;
	r = piv_reserve(p, b->count);
	if (r)
		return r;
	for (i = 0; i < b->count; i++) {
		r = piv_batch_crypt(b, i, ivs + i * 16);
		if (r)
			return r;
	}
	if (READ_ONCE(p->failed))
		return -EIO;
	r = piv_batch_submit(b, REQ_OP_WRITE | REQ_SYNC, mutated);
	if (!r && flush)
		r = piv_flush(p);
	return r;
}

/* A replay-only activation can leave valid committed journal entries on disk:
 * native postsuspend initializes the journal only after wrote_to_journal. Copy
 * one authenticated CURRENT tuple through the same target before END. This is
 * not encryption, consumes no nonce, and needs no external recovery plan because
 * every byte is identical, so it cannot tear a sector even on a direct-mode
 * (stock persistent no-journal) lower device, where it is merely redundant.
 * The first sector of the keyslot area that reads and authenticates is used, so
 * one damaged or unreadable sector (e.g. sector 0, a keyslot replica) cannot
 * block setup, END or DETACH. The write is followed by a flush (which also
 * commits a journal), so it needs no FUA of its own.
 */
#define PIV_CHECKPOINT_SECTORS 112
static int piv_checkpoint(struct piv_control *p)
{
	struct piv_crypt *cc = p->cc;
	u8 *saved = kmalloc(cc->sector_size + cc->tuple_size, GFP_NOIO);
	u64 i;
	int ret = -EIO;

	if (!saved)
		return -ENOMEM;
	for (i = 0; i < PIV_CHECKPOINT_SECTORS && i < p->profile.sectors; i++) {
		struct piv_batch *b = NULL;
		u8 *data, *tuple;

		ret = piv_batch_alloc(p, i, 1, false, &b);
		if (ret)
			break;
		data = page_address(b->pages[0]);
		tuple = piv_batch_tuple(b, 0);
		ret = piv_batch_submit(b, REQ_OP_READ, NULL);
		if (!ret) {
			/* Keep the stored copy; authentication decrypts in place. */
			memcpy(saved, data, cc->sector_size);
			memcpy(saved + cc->sector_size, tuple, cc->tuple_size);
			ret = piv_batch_crypt(b, 0, NULL);
		}
		if (ret) {
			/* Unreadable or failing authentication: try the next sector. */
			piv_batch_free(b);
			if (ret == -ENOMEM)
				break;
			continue;
		}
		memcpy(data, saved, cc->sector_size);
		memcpy(tuple, saved + cc->sector_size, cc->tuple_size);
		ret = piv_batch_submit(b, REQ_OP_WRITE | REQ_SYNC, NULL);
		if (!ret)
			ret = piv_flush(p);
		piv_batch_free(b);
		break;
	}
	kfree_sensitive(saved);
	return ret;
}

#include "piv-native.inc"

static long piv_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct piv_control *p = file->private_data;
	struct piv_read_iv read;
	struct piv_query profile;
	struct piv_native_status status = {};
	struct piv_native_setup *setup = NULL;
	struct piv_native_keyslot *keyslot = NULL;
	unsigned int noio;
	long ret = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (cmd != PIV_QUERY && cmd != PIV_DEVICES && cmd != PIV_BEGIN && cmd != PIV_END &&
	    cmd != PIV_NATIVE_SETUP && cmd != PIV_NATIVE_DETACH && cmd != PIV_NATIVE_STATUS &&
	    cmd != PIV_NATIVE_KEYSLOT)
		return -ENOTTY;
	if (cmd == PIV_NATIVE_SETUP) {
		setup = memdup_user((void __user *)arg, sizeof(*setup));
		if (IS_ERR(setup)) return PTR_ERR(setup);
		if (setup->version != 6 || setup->size != sizeof(*setup)) {
			ret = -EINVAL; goto out;
		}
		/* Early boot: wait for seeded CRNG without holding owner lifecycle lock. */
		ret = wait_for_random_bytes();
		if (ret) goto out;
	} else if (cmd == PIV_NATIVE_KEYSLOT) {
		keyslot = memdup_user((void __user *)arg, sizeof(*keyslot));
		if (IS_ERR(keyslot)) return PTR_ERR(keyslot);
		ret = wait_for_random_bytes();
		if (ret) goto out;
	} else if (cmd != PIV_QUERY && cmd != PIV_DEVICES && cmd != PIV_NATIVE_STATUS &&
		   copy_from_user(&read, (void __user *)arg, sizeof(read))) {
		return -EFAULT;
	}
	if (cmd == PIV_NATIVE_SETUP) {
		ret = mutex_lock_interruptible(&p->lock);
		if (ret) { ret = -EINTR; goto out; }
	} else {
		mutex_lock(&p->lock);
	}
	noio = memalloc_noio_save();
	if (!p->live)
		ret = -ENODEV;
	else if (cmd == PIV_NATIVE_STATUS) {
		status.generation = p->profile.generation; status.version = 5;
		status.encryptions = atomic64_read(&p->encryptions);
		status.failed = READ_ONCE(p->failed);
		if (p->native) {
			status.active = 1; status.views = p->native->views;
			status.failed |= READ_ONCE(p->native->failed);
			status.hidden_bytes = p->native->hidden_bytes;
			status.corrected = atomic64_read(&p->native->corrected);
			status.parity = p->native->parity; status.ab = p->native->ab;
		}
	} else if (cmd == PIV_NATIVE_SETUP)
		ret = pn_setup(p, file, setup);
	else if (cmd == PIV_NATIVE_KEYSLOT) {
		/* Exclusive: drains view requests, which read keyslot/directory state. */
		down_write(&p->io);
		ret = pn_keyslot(p, keyslot);
		up_write(&p->io);
	}
	else if (cmd == PIV_NATIVE_DETACH) {
		ret = piv_identity(p, read.version, read.size, read.generation, read.sector, sizeof(read));
		if (!ret && (read.sector || memchr_inv(read.iv, 0, sizeof(read.iv)) || memchr_inv(read.reserved, 0, sizeof(read.reserved)))) ret = -EINVAL;
		if (!ret && (!p->native || p->native->views)) ret = -EBUSY;
		if (!ret && !READ_ONCE(p->failed) && !READ_ONCE(p->native->failed)) {
			ret = piv_checkpoint(p);
			if (ret) { WRITE_ONCE(p->failed, true); WRITE_ONCE(p->native->failed, true); }
		}
		/* No view exists; @io exclusive anyway, per the owner-state rule. */
		if (!ret) { down_write(&p->io); pn_free(p->native); p->native = NULL; up_write(&p->io); }
	} else if (cmd == PIV_QUERY || cmd == PIV_DEVICES)
		profile = p->profile;
	else if (p->native)
		ret = -EBUSY;
	else {
		/* BEGIN/END bracket native SETUP on a quiesced owner. */
		ret = piv_identity(p, read.version, read.size, read.generation,
				   read.sector, sizeof(read));
		if (!ret && (read.sector || memchr_inv(read.iv, 0, sizeof(read.iv)) ||
			     memchr_inv(read.reserved, 0, sizeof(read.reserved))))
			ret = -EINVAL;
		if (!ret && (!piv_quiesced(p) || READ_ONCE(p->failed)))
			ret = READ_ONCE(p->failed) ? -EIO : -EBUSY;
		if (!ret && cmd == PIV_BEGIN) {
			if (p->controller && p->controller != file)
				ret = -EBUSY;
			else {
				p->transaction = true;
				p->controller = file;
			}
		} else if (!ret) {
			if (!p->transaction || p->controller != file)
				ret = -EPERM;
			else {
				ret = piv_checkpoint(p);
				if (!ret) {
					p->transaction = false;
					p->controller = NULL;
				} else
					WRITE_ONCE(p->failed, true);
			}
		}
	}
	memalloc_noio_restore(noio);
	mutex_unlock(&p->lock);
	if (!ret) {
		if (cmd == PIV_NATIVE_STATUS)
			ret = copy_to_user((void __user *)arg, &status, sizeof(status)) ? -EFAULT : 0;
		else if (cmd == PIV_DEVICES)
			ret = copy_to_user((void __user *)arg, &p->devices, sizeof(p->devices)) ? -EFAULT : 0;
		else if (cmd == PIV_QUERY)
			ret = copy_to_user((void __user *)arg, &profile, sizeof(profile)) ? -EFAULT : 0;
		else if (cmd == PIV_NATIVE_SETUP) {
			/* Output counts; never copy the key back. A copy failure after a
			 * successful setup leaves the owner active (as for STATUS).
			 */
			memzero_explicit(setup->key, sizeof(setup->key));
			ret = copy_to_user((void __user *)arg, setup, sizeof(*setup)) ? -EFAULT : 0;
		}
	}
out:
	kfree_sensitive(setup);
	kfree_sensitive(keyslot);
	return ret;
}

static int piv_preresume(struct dm_target *ti)
{
	struct piv_crypt *cc = ti->private;
	struct piv_control *p = cc->piv_control;
	int ret = 0;
	if (!p)
		return 0;
	mutex_lock(&p->lock);
	if (READ_ONCE(p->failed) || p->transaction ||
	    !test_bit(PIV_KEY_VALID, &cc->flags))
		ret = -EBUSY;
	else
		p->resuming = true;
	mutex_unlock(&p->lock);
	return ret;
}

/* presuspend runs before upper I/O drains or lower tables are suspended. */
static void piv_presuspend(struct dm_target *ti)
{
	struct piv_crypt *cc = ti->private;
	struct piv_control *p = cc->piv_control;
	if (!p)
		return;
	mutex_lock(&p->lock);
	/* Exclusive @io waits for in-flight view requests to finish. */
	down_write(&p->io);
	p->blocked = true;
	p->resuming = false;
	up_write(&p->io);
	mutex_unlock(&p->lock);
}

static void piv_unblock(struct dm_target *ti)
{
	struct piv_crypt *cc = ti->private;
	struct piv_control *p = cc->piv_control;
	if (!p)
		return;
	mutex_lock(&p->lock);
	down_write(&p->io);
	p->blocked = false;
	p->activated = true;
	p->resuming = false;
	up_write(&p->io);
	mutex_unlock(&p->lock);
}

static const struct file_operations piv_fops = {
	.owner = THIS_MODULE,
	.open = piv_open,
	.release = piv_release,
	.unlocked_ioctl = piv_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = compat_ptr_ioctl,
#endif
};

static int piv_register(struct piv_crypt *cc, struct dm_target *ti)
{
	struct piv_control *p;
	int ret;

	/* Pin the tested stock profiles (16-byte random IVs for format v5: AEGIS-128
	 * or XTS + HMAC authenc); this is not a general API. The constructor already
	 * parsed the profile; re-check the invariants this code relies on.
	 */
	if ((cc->sector_size != 512 && cc->sector_size != 4096) ||
	    cc->iv_size != 16 ||
	    cc->integrity_tag_size > PIV_MAX_TAG || cc->tuple_size != cc->integrity_tag_size + cc->iv_size ||
	    !(dm_table_get_mode(ti->table) & BLK_OPEN_WRITE)) {
		ti->error = "piv_control requires the tested writable-owner AEAD profile";
		return -EINVAL;
	}
	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		return -ENOMEM;
	kref_init(&p->refs);
	INIT_WORK(&p->free_work, piv_free_work);
	mutex_init(&p->lock);
	init_rwsem(&p->io);
	spin_lock_init(&p->ranges_lock);
	INIT_LIST_HEAD(&p->ranges);
	init_waitqueue_head(&p->ranges_wait);
	atomic64_set(&p->encryptions, 0);
	atomic64_set(&p->writes_done, 0);
	atomic64_set(&p->flushed, 0);
	p->live = true;
	p->blocked = true;
	p->cc = cc;
	p->profile = (struct piv_query) {
		.version = PIV_CONTROL_VERSION, .size = sizeof(struct piv_query),
		.generation = atomic64_inc_return(&piv_generation),
		.sectors = ti->len >> cc->sector_shift,
		.sector_size = cc->sector_size, .iv_size = cc->iv_size,
		.tag_size = cc->integrity_tag_size, .tuple_size = cc->tuple_size,
	};
	p->devices = (struct piv_devices) {
		.owner_major = MAJOR(disk_devt(dm_disk(dm_table_get_md(ti->table)))),
		.owner_minor = MINOR(disk_devt(dm_disk(dm_table_get_md(ti->table)))),
		.lower_major = MAJOR(cc->dev->bdev->bd_dev),
		.lower_minor = MINOR(cc->dev->bdev->bd_dev),
	};
	snprintf(p->name, sizeof(p->name), "pivctl-%llu",
		 (unsigned long long)p->profile.generation);
	/* Unbound and concurrent; requests touching the same sectors or record
	 * serialize on range locks (piv_range_lock). Reclaim-capable: writeback
	 * through the views must progress under memory pressure.
	 */
	p->wq = alloc_workqueue("piv-native-%llu", WQ_MEM_RECLAIM | WQ_UNBOUND, PN_MAX_ACTIVE,
				(unsigned long long)p->profile.generation);
	if (!p->wq) {
		kref_put(&p->refs, piv_free);
		return -ENOMEM;
	}
	p->misc = (struct miscdevice) {
		.minor = MISC_DYNAMIC_MINOR, .name = p->name,
		.fops = &piv_fops, .mode = 0600,
	};
	ret = misc_register(&p->misc);
	if (ret) {
		kref_put(&p->refs, piv_free);
		return ret;
	}
	cc->piv_control = p;
	mutex_lock(&piv_controls_lock); list_add_tail(&p->list, &piv_controls); mutex_unlock(&piv_controls_lock);
	return 0;
}

static void piv_unregister(struct piv_crypt *cc)
{
	struct piv_control *p = cc->piv_control;
	if (!p)
		return;
	mutex_lock(&piv_controls_lock); list_del(&p->list); mutex_unlock(&piv_controls_lock);
	mutex_lock(&p->lock);
	down_write(&p->io);
	p->live = false;
	p->blocked = true;
	p->cc = NULL;
	pn_free(p->native); p->native = NULL;
	up_write(&p->io);
	mutex_unlock(&p->lock);
	misc_deregister(&p->misc);
	kref_put(&p->refs, piv_free);
	cc->piv_control = NULL;
}
