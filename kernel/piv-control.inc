#include <crypto/hash.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <linux/highmem.h>
#include <linux/sort.h>
#include <linux/vmalloc.h>
#include <linux/unaligned.h>
#include <linux/rbtree.h>
#include <linux/sched/signal.h>
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
	bool live;
	bool blocked;
	bool activated;
	bool resuming;
	bool transaction;
	bool failed;
	u64 encryptions;
	struct file *controller;
	struct piv_crypt *cc;
	struct piv_query profile;
	struct piv_devices devices;
	char name[40];
};

static void piv_free(struct kref *ref)
{
	kfree(container_of(ref, struct piv_control, refs));
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

struct piv_sector {
	struct piv_io io;
	struct page *page;
	struct bio *bio;
	u8 original[PIV_TUPLE_BYTES];
	bool bad;	/* piv_load_mode(allow_bad): stored tuple failed authentication */
};

static void piv_sector_free(struct piv_crypt *cc, struct piv_sector *s)
{
	if (!s)
		return;
	if (s->bio)
		bio_put(s->bio);
	if (s->page) {
		memzero_explicit(page_address(s->page), PAGE_SIZE);
		__free_page(s->page);
	}
	kfree_sensitive(s->io.integrity_metadata);
	kfree_sensitive(s);
}

static int piv_bio(struct piv_crypt *cc, struct piv_sector *s, blk_opf_t op)
{
	if (s->bio)
		bio_put(s->bio);
	s->bio = bio_alloc(cc->dev->bdev, 1, op, GFP_NOIO);
	if (!s->bio)
		return -ENOMEM;
	s->bio->bi_iter.bi_sector = cc->start + s->io.sector;
	if (bio_add_page(s->bio, s->page, cc->sector_size, 0) != cc->sector_size)
		return -ENOMEM;
	return piv_integrity_alloc(&s->io, s->bio);
}

/* Write bios encrypt with the requested IV; read bios authenticate/decrypt. */
static int piv_crypto(struct piv_crypt *cc, struct piv_sector *s,
		      const u8 *iv)
{
	return piv_aead(cc, s->io.sector, s->page, 0, s->io.integrity_metadata, iv,
			op_is_write(bio_op(s->bio)));
}

/* Caller holds lifecycle lock. Plaintext lives only in a private wiped page.
 * With @allow_bad, a sector whose stored tuple fails authentication (-EBADMSG,
 * e.g. torn by a crash without the integrity journal) is returned with ->bad set
 * and its raw stored ciphertext/tuple in ->original; its page is not plaintext.
 * Only internal full-sector replacement and SIV-protected fragment collection
 * may use that; nothing unauthenticated is ever published.
 */
static noinline int piv_load_mode(struct piv_crypt *cc, u64 index, struct piv_sector **out, bool allow_bad)
{
	struct piv_sector *s;
	struct bvec_iter saved;
	int ret = -ENOMEM;

	s = kzalloc(sizeof(*s), GFP_NOIO);
	if (!s)
		return ret;
	s->io.cc = cc;
	s->io.sector = index << cc->sector_shift;
	s->io.integrity_metadata = kzalloc(cc->tuple_size, GFP_NOIO);
	s->page = alloc_page(GFP_NOIO | __GFP_ZERO);
	if (!s->io.integrity_metadata || !s->page)
		goto bad;
	ret = piv_bio(cc, s, REQ_OP_READ);
	if (ret)
		goto bad;
	saved = s->bio->bi_iter;
	ret = submit_bio_wait(s->bio);
	if (ret)
		goto bad;
	s->bio->bi_iter = saved;
	memcpy(s->original, page_address(s->page), cc->sector_size);
	memcpy(s->original + 4096, s->io.integrity_metadata, cc->tuple_size);
	ret = piv_crypto(cc, s, NULL);
	if (ret == -EBADMSG && allow_bad) {
		s->bad = true;
		ret = 0;
	}
	if (ret)
		goto bad;
	*out = s;
	return 0;
bad:
	piv_sector_free(cc, s);
	return ret;
}

static int piv_load(struct piv_crypt *cc, u64 index, struct piv_sector **out)
{
	return piv_load_mode(cc, index, out, false);
}

/* Bounded lower reads; outputs are published only after every sector verifies.
 * No cache: all calls fetch current tuples through the same integrity device.
 */
#define PIV_READ_BYTES 16384
struct piv_range_io {
 struct piv_io io;
 struct bio *bio;
 struct page *pages[PIV_READ_BYTES / PAGE_SIZE];
};
static int piv_read_range(struct piv_control *p, u64 index, u32 count,
                          u8 *data, u8 *ivs)
{
 struct piv_crypt *cc = p->cc;
 struct piv_range_io *r;
 u32 i, bytes, pages;
 int ret = -ENOMEM;
 if (!count || count > PIV_READ_BYTES / cc->sector_size ||
     index >= p->profile.sectors || count > p->profile.sectors - index)
  return -EINVAL;
 bytes = count * cc->sector_size; pages = DIV_ROUND_UP(bytes, PAGE_SIZE);
 r = kzalloc(sizeof(*r), GFP_NOIO); if (!r) return -ENOMEM;
 r->io.cc = cc; r->io.sector = index << cc->sector_shift;
 r->io.integrity_metadata = kzalloc(count * cc->tuple_size, GFP_NOIO);
 r->bio = bio_alloc(cc->dev->bdev, pages, REQ_OP_READ, GFP_NOIO);
 if (!r->io.integrity_metadata || !r->bio) goto done;
 r->bio->bi_iter.bi_sector = cc->start + r->io.sector;
 for (i = 0; i < pages; i++) {
  u32 length = min_t(u32, PAGE_SIZE, bytes - i * PAGE_SIZE);
  r->pages[i] = alloc_page(GFP_NOIO | __GFP_ZERO);
  if (!r->pages[i] || bio_add_page(r->bio, r->pages[i], length, 0) != length) goto done;
 }
 ret = piv_integrity_alloc(&r->io, r->bio); if (ret) goto done;
 ret = submit_bio_wait(r->bio); if (ret) goto done;
 /* Authenticate every sector with its own address/IV AAD before publishing. */
 for (i = 0; i < count; i++) {
  u32 at = i * cc->sector_size;
  ret = piv_aead(cc, r->io.sector + ((u64)i << cc->sector_shift), r->pages[at >> PAGE_SHIFT],
                 at & ~PAGE_MASK, r->io.integrity_metadata + i * cc->tuple_size, NULL, false);
  if (ret) goto done;
 }
 for (i = 0; data && i < pages; i++)
  memcpy(data + i * PAGE_SIZE, page_address(r->pages[i]), min_t(u32, PAGE_SIZE, bytes - i * PAGE_SIZE));
 for (i = 0; ivs && i < count; i++)
  memcpy(ivs + i * cc->iv_size, r->io.integrity_metadata + i * cc->tuple_size + 16, cc->iv_size);
done:
 if (r->bio) bio_put(r->bio);
 for (i = 0; i < pages; i++) if (r->pages[i]) {
  memzero_explicit(page_address(r->pages[i]), PAGE_SIZE); __free_page(r->pages[i]);
 }
 kfree_sensitive(r->io.integrity_metadata); kfree_sensitive(r);
 return ret;
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

static int piv_read_iv(struct piv_control *p, struct piv_read_iv *out, bool quiesced)
{
	struct piv_sector *s = NULL;
	int ret;

	ret = piv_identity(p, out->version, out->size, out->generation,
			   out->sector, sizeof(*out));
	if (ret)
		return ret;
	if (memchr_inv(out->iv, 0, sizeof(out->iv)) ||
	    memchr_inv(out->reserved, 0, sizeof(out->reserved)))
		return -EINVAL;
	if (quiesced ? !piv_quiesced(p) : p->blocked)
		return -EBUSY;
	ret = piv_load(p->cc, out->sector, &s);
	if (!ret)
		memcpy(out->iv, s->original + 4112, p->profile.iv_size);
	piv_sector_free(p->cc, s);
	return ret;
}

/* @replace (internal primary updates only): the old sector may fail
 * authentication; its full plaintext is replaced, so nothing of it is kept
 * except the raw stored IV used as expected_iv and for fragment refresh.
 */
static int piv_update(struct piv_control *p, struct file *file,
		      struct piv_update *u, bool prepare, bool primary, bool internal, bool replace)
{
	struct piv_crypt *cc = p->cc;
	struct piv_sector *old = NULL, *candidate = NULL;
	int ret;

	ret = piv_identity(p, u->version, u->size, u->generation,
			   u->sector, sizeof(*u));
	if (ret)
		return ret;
	/* Fixed-size control tuples pad unused data bytes in RAM only. */
	if (memchr_inv(u->tuple + cc->sector_size, 0, 4096 - cc->sector_size) ||
	    memchr_inv(u->tuple + 4112 + cc->iv_size, 0, 16 - cc->iv_size) ||
	    memchr_inv(u->expected_iv + cc->iv_size, 0, 16 - cc->iv_size))
		return -EINVAL;
	if (u->reserved || (u->flags && (prepare || u->flags != PIV_APPLY_DEFER_FLUSH)))
		return -EINVAL;
	if (!internal && (!piv_quiesced(p) || !p->transaction || p->controller != file))
		return -EBUSY;
	if (p->failed)
		return -EIO;
	if (prepare && memchr_inv(u->tuple + (primary ? 4096 : 0), 0, primary ? 16 : 4112))
		return -EINVAL;
	if (replace && (!internal || !primary))
		return -EINVAL;
	ret = piv_load_mode(cc, u->sector, &old, replace);
	if (ret)
		goto done;
	/* Exact replay performs no new encryption or changed data write. */
	if (!prepare && !memcmp(old->original, u->tuple, PIV_TUPLE_BYTES)) {
		ret = u->flags ? 0 : blkdev_issue_flush(cc->dev->bdev);
		goto io_done;
	}
	if (memcmp(old->original + 4112, u->expected_iv, cc->iv_size)) {
		ret = -ESTALE;
		goto done;
	}
	if (!memcmp(u->tuple + 4112, u->expected_iv, cc->iv_size)) {
		ret = -EINVAL;
		goto done;
	}
	if (prepare) {
		if (p->encryptions >= (1ULL << 32)) {
			ret = -EDQUOT;
			goto done;
		}
		ret = piv_bio(cc, old, REQ_OP_WRITE);
		if (ret)
			goto done;
		p->encryptions++;
		if (primary)
			memcpy(page_address(old->page), u->tuple, cc->sector_size);
		ret = piv_crypto(cc, old, u->tuple + 4112);
		if (!ret) {
			memcpy(u->tuple, page_address(old->page), cc->sector_size);
			memcpy(u->tuple + 4096, old->io.integrity_metadata, cc->tuple_size);
		}
		goto done;
	}
	/* Authenticate candidate; hidden-only APPLY also requires identical plaintext. */
	candidate = kzalloc(sizeof(*candidate), GFP_NOIO);
	if (!candidate) {
		ret = -ENOMEM;
		goto done;
	}
	candidate->io.cc = cc;
	candidate->io.sector = old->io.sector;
	candidate->page = alloc_page(GFP_NOIO | __GFP_ZERO);
	candidate->io.integrity_metadata = kmemdup(u->tuple + 4096, cc->tuple_size, GFP_NOIO);
	if (!candidate->page || !candidate->io.integrity_metadata) {
		ret = -ENOMEM;
		goto done;
	}
	memcpy(page_address(candidate->page), u->tuple, cc->sector_size);
	ret = piv_bio(cc, candidate, REQ_OP_READ);
	if (ret)
		goto done;
	ret = piv_crypto(cc, candidate, NULL);
	if (ret)
		goto done;
	if (!primary && memcmp(page_address(candidate->page), page_address(old->page), cc->sector_size)) {
		ret = -EPERM;
		goto done;
	}
	/* Submit exact precomputed ciphertext plus tag/IV through lower journaling. */
	memcpy(page_address(old->page), u->tuple, cc->sector_size);
	memcpy(old->io.integrity_metadata, u->tuple + 4096, cc->tuple_size);
	ret = piv_bio(cc, old, REQ_OP_WRITE | REQ_SYNC | (u->flags ? 0 : REQ_FUA));
	if (ret)
		goto done;
	ret = submit_bio_wait(old->bio);
	if (!ret && !u->flags)
		ret = blkdev_issue_flush(cc->dev->bdev);
io_done:
	if (ret)
		p->failed = true;
done:
	piv_sector_free(cc, candidate);
	piv_sector_free(cc, old);
	return ret;
}

/* A replay-only activation can leave valid committed journal entries on disk:
 * native postsuspend initializes the journal only after wrote_to_journal. Copy
 * one authenticated CURRENT tuple through the same target before END. This is
 * not encryption, consumes no nonce, and needs no external recovery plan because
 * every byte is identical. Native journaling still protects its sector atomicity.
 */
static int piv_checkpoint(struct piv_crypt *cc)
{
	struct piv_sector *s = NULL;
	int ret;

	ret = piv_load(cc, 0, &s);
	if (ret)
		return ret;
	memcpy(page_address(s->page), s->original, cc->sector_size);
	memcpy(s->io.integrity_metadata, s->original + 4096, cc->tuple_size);
	ret = piv_bio(cc, s, REQ_OP_WRITE | REQ_SYNC | REQ_FUA);
	if (!ret)
		ret = submit_bio_wait(s->bio);
	if (!ret)
		ret = blkdev_issue_flush(cc->dev->bdev);
	piv_sector_free(cc, s);
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
	struct piv_update *update = NULL;
	bool preparing = cmd == PIV_PREPARE || cmd == PIV_PREPARE_PRIMARY;
	bool primary = cmd == PIV_PREPARE_PRIMARY || cmd == PIV_APPLY_PRIMARY;
	bool updating = preparing || cmd == PIV_APPLY || cmd == PIV_APPLY_PRIMARY;
	bool data_request = updating || cmd == PIV_READ_PRIMARY;
	unsigned int noio;
	long ret = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (cmd != PIV_QUERY && cmd != PIV_DEVICES && cmd != PIV_READ_IV && cmd != PIV_READ_QUIESCED &&
	    cmd != PIV_BEGIN && cmd != PIV_END && cmd != PIV_SYNC &&
	    cmd != PIV_NATIVE_SETUP && cmd != PIV_NATIVE_DETACH && cmd != PIV_NATIVE_STATUS &&
	    cmd != PIV_NATIVE_KEYSLOT && !data_request)
		return -ENOTTY;
	if (cmd == PIV_NATIVE_SETUP) {
		setup = memdup_user((void __user *)arg, sizeof(*setup));
		if (IS_ERR(setup)) return PTR_ERR(setup);
		if (setup->version != 4 || setup->size != sizeof(*setup)) {
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
	} else if (data_request) {
		update = memdup_user((void __user *)arg, sizeof(*update));
		if (IS_ERR(update))
			return PTR_ERR(update);
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
		status.generation = p->profile.generation; status.version = 3;
		status.encryptions = p->encryptions;
		if (p->native) {
			status.active = 1; status.views = p->native->views; status.failed = p->native->failed;
			status.hidden_bytes = p->native->hidden_bytes;
		}
	} else if (cmd == PIV_NATIVE_SETUP)
		ret = pn_setup(p, file, setup);
	else if (cmd == PIV_NATIVE_KEYSLOT)
		ret = pn_keyslot(p, keyslot);
	else if (cmd == PIV_NATIVE_DETACH) {
		ret = piv_identity(p, read.version, read.size, read.generation, read.sector, sizeof(read));
		if (!ret && (read.sector || memchr_inv(read.iv, 0, sizeof(read.iv)) || memchr_inv(read.reserved, 0, sizeof(read.reserved)))) ret = -EINVAL;
		if (!ret && (!p->native || p->native->views)) ret = -EBUSY;
		if (!ret && !p->failed && !p->native->failed) {
			ret = piv_checkpoint(p->cc);
			if (ret) { p->failed = true; p->native->failed = true; }
		}
		if (!ret) { pn_free(p->native); p->native = NULL; }
	} else if (p->native && cmd != PIV_QUERY && cmd != PIV_DEVICES)
		ret = -EBUSY;
	else if (updating)
		ret = piv_update(p, file, update, preparing, primary, false, false);
	else if (cmd == PIV_READ_PRIMARY) {
		struct piv_sector *sector = NULL;
		ret = piv_identity(p, update->version, update->size, update->generation,
				   update->sector, sizeof(*update));
		if (!ret && (update->flags || update->reserved ||
		    memchr_inv(update->expected_iv, 0, sizeof(update->expected_iv)) ||
		    memchr_inv(update->tuple, 0, PIV_TUPLE_BYTES)))
			ret = -EINVAL;
		if (!ret && (p->blocked || p->failed))
			ret = -EBUSY;
		if (!ret)
			ret = piv_load(p->cc, update->sector, &sector);
		if (!ret) {
			memcpy(update->tuple, page_address(sector->page), p->profile.sector_size);
			memcpy(update->tuple + 4112, sector->original + 4112, p->profile.iv_size);
		}
		piv_sector_free(p->cc, sector);
	} else if (cmd == PIV_READ_IV || cmd == PIV_READ_QUIESCED)
		ret = piv_read_iv(p, &read, cmd == PIV_READ_QUIESCED);
	else if (cmd == PIV_QUERY || cmd == PIV_DEVICES)
		profile = p->profile;
	else {
		ret = piv_identity(p, read.version, read.size, read.generation,
				   read.sector, sizeof(read));
		if (!ret && (read.sector || memchr_inv(read.iv, 0, sizeof(read.iv)) ||
			     memchr_inv(read.reserved, 0, sizeof(read.reserved))))
			ret = -EINVAL;
		if (!ret && (!piv_quiesced(p) || p->failed))
			ret = p->failed ? -EIO : -EBUSY;
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
				ret = cmd == PIV_END ? piv_checkpoint(p->cc) :
					blkdev_issue_flush(p->cc->dev->bdev);
				if (!ret && cmd == PIV_END) {
					p->transaction = false;
					p->controller = NULL;
				} else if (ret)
					p->failed = true;
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
		else if (cmd == PIV_READ_IV || cmd == PIV_READ_QUIESCED)
			ret = copy_to_user((void __user *)arg, &read, sizeof(read)) ? -EFAULT : 0;
		else if (preparing || cmd == PIV_READ_PRIMARY)
			ret = copy_to_user((void __user *)arg, update, sizeof(*update)) ? -EFAULT : 0;
	}
out:
	kfree_sensitive(update);
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
	if (p->failed || p->transaction ||
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
	p->blocked = true;
	p->resuming = false;
	mutex_unlock(&p->lock);
}

static void piv_unblock(struct dm_target *ti)
{
	struct piv_crypt *cc = ti->private;
	struct piv_control *p = cc->piv_control;
	if (!p)
		return;
	mutex_lock(&p->lock);
	p->blocked = false;
	p->activated = true;
	p->resuming = false;
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

	/* Pin the tested crypto profile (AEGIS-128, format v4); this is not a
	 * general API. The constructor already parsed it; re-check the invariants
	 * this code relies on.
	 */
	if (strcmp(cc->cipher_string, "capi:aegis128-random") ||
	    cc->key_size != 16 || (cc->sector_size != 512 && cc->sector_size != 4096) ||
	    cc->iv_size != 16 || cc->integrity_iv_size != cc->iv_size ||
	    cc->integrity_tag_size != 16 || cc->tuple_size != 16 + cc->iv_size ||
	    cc->iv_offset || cc->start ||
	    !(dm_table_get_mode(ti->table) & BLK_OPEN_WRITE)) {
		ti->error = "piv_control requires the tested writable-owner AEAD profile";
		return -EINVAL;
	}
	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		return -ENOMEM;
	kref_init(&p->refs);
	mutex_init(&p->lock);
	p->live = true;
	p->blocked = true;
	p->cc = cc;
	p->profile = (struct piv_query) {
		.version = PIV_CONTROL_VERSION, .size = sizeof(struct piv_query),
		.generation = atomic64_inc_return(&piv_generation),
		.sectors = ti->len >> cc->sector_shift,
		.sector_size = cc->sector_size, .iv_size = cc->iv_size,
		.tag_size = cc->integrity_tag_size, .tuple_size = cc->tuple_size,
		.flags = PIV_QUERY_LOWER_WRITE | PIV_QUERY_PRIMARY_FILTER | PIV_QUERY_MUTATION | PIV_QUERY_PRIMARY_CONTROL,
	};
	p->devices = (struct piv_devices) {
		.owner_major = MAJOR(disk_devt(dm_disk(dm_table_get_md(ti->table)))),
		.owner_minor = MINOR(disk_devt(dm_disk(dm_table_get_md(ti->table)))),
		.lower_major = MAJOR(cc->dev->bdev->bd_dev),
		.lower_minor = MINOR(cc->dev->bdev->bd_dev),
	};
	snprintf(p->name, sizeof(p->name), "pivctl-%llu",
		 (unsigned long long)p->profile.generation);
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
	p->live = false;
	p->blocked = true;
	p->cc = NULL;
	pn_free(p->native); p->native = NULL;
	mutex_unlock(&p->lock);
	misc_deregister(&p->misc);
	kref_put(&p->refs, piv_free);
	cc->piv_control = NULL;
}
