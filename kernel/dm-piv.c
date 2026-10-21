// SPDX-License-Identifier: GPL-2.0-only
/*
 * dm-piv: standalone persistent-IV owner (piv-crypt) and paired views (piv-view).
 *
 * This replaces the former private fork of dm-crypt. It implements only what the
 * project needs: per-sector AEAD over a stock dm-integrity device, reproducing
 * the Linux dm-crypt LUKS2 on-disk layout for the pinned random-IV AEAD
 * profiles (AAD = LE64(512-byte sector) || IV; integrity tuple = tag || IV).
 * The owner serves authenticated reads until native ownership starts; it never
 * accepts ordinary writes. Stock dm-crypt stays loaded and independent.
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/blk-integrity.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/scatterlist.h>
#include <linux/miscdevice.h>
#include <linux/kref.h>
#include <linux/uaccess.h>
#include <linux/compat.h>
#include <linux/sched/mm.h>
#include <linux/kernel.h>
#include <crypto/aead.h>
#include <crypto/aes.h>
#include <crypto/skcipher.h>
#include <crypto/utils.h>
#include <crypto/hash.h>
#include <linux/device-mapper.h>
#include "piv-control.h"

#define DM_MSG_PREFIX "piv-crypt"

enum { PIV_KEY_VALID, PIV_SUSPENDED };

struct piv_control;

struct piv_crypt {
	struct dm_dev *dev;
	struct crypto_aead *tfm;
	struct piv_control *piv_control;
	unsigned long flags;
	sector_t start;
	u64 iv_offset;
	unsigned int sector_size, sector_shift, iv_size, integrity_iv_size;
	unsigned int integrity_tag_size, tuple_size, key_size;
	char cipher_string[48];
	u8 key[32];
};

/* Mirrors the dm-crypt fields this code uses for one integrity-backed request. */
struct piv_io {
	struct piv_crypt *cc;
	sector_t sector;		/* 512-byte units relative to the target */
	u8 *integrity_metadata;		/* tuple_size bytes per encryption sector */
};

static const struct piv_profile {
	const char *cipher_string, *algorithm;
	unsigned int key_size, iv_size;
} piv_profiles[] = {
	{ "capi:gcm(aes)-random", "gcm(aes)", 32, 12 },
	{ "capi:rfc7539(chacha20,poly1305)-random", "rfc7539(chacha20,poly1305)", 32, 12 },
	{ "capi:aegis128-random", "aegis128", 16, 16 },
};

static struct workqueue_struct *piv_io_wq;

/* Attach the caller's integrity buffer so dm-integrity reads/writes the tuples. */
static int piv_integrity_alloc(struct piv_io *io, struct bio *bio)
{
	struct bio_integrity_payload *bip;
	unsigned int tag_len;

	if (!bio_sectors(bio))
		return 0;
	bip = bio_integrity_alloc(bio, GFP_NOIO, 1);
	if (IS_ERR(bip))
		return PTR_ERR(bip);
	tag_len = io->cc->tuple_size * (bio_sectors(bio) >> io->cc->sector_shift);
	bip->bip_iter.bi_sector = io->cc->start + io->sector;
	if (bio_integrity_add_page(bio, virt_to_page(io->integrity_metadata), tag_len,
				   offset_in_page(io->integrity_metadata)) != tag_len)
		return -ENOMEM;
	return 0;
}

/*
 * One encryption sector, in place, exactly as dm-crypt's AEAD path:
 *   | AAD: LE64(sector512 - iv_offset) | IV | data (sector_size) | tag (16) |
 * Encryption stores the IV after the tag in @tuple and zero-fills any padding;
 * decryption takes the IV from @tuple and fails with -EBADMSG on mismatch.
 * Buffers given to scatterlists are heap memory (never the stack).
 */
struct piv_aead_buffers {
	__le64 sector;
	u8 org_iv[16];
	u8 iv[16];
};

static int piv_aead(struct piv_crypt *cc, sector_t sector512, struct page *page,
		    unsigned int offset, u8 *tuple, const u8 *requested_iv, bool encrypt)
{
	struct piv_aead_buffers *b;
	struct aead_request *req;
	struct scatterlist sg[4];
	DECLARE_CRYPTO_WAIT(wait);
	int r;

	if (encrypt && !requested_iv)
		return -EINVAL;	/* The owner never generates IVs itself. */
	b = kzalloc(sizeof(*b), GFP_NOIO);
	req = aead_request_alloc(cc->tfm, GFP_NOIO);
	if (!b || !req) {
		r = -ENOMEM;
		goto out;
	}
	b->sector = cpu_to_le64(sector512 - cc->iv_offset);
	if (encrypt) {
		memcpy(b->org_iv, requested_iv, cc->iv_size);
		memcpy(tuple + cc->integrity_tag_size, b->org_iv, cc->iv_size);
	} else {
		memcpy(b->org_iv, tuple + cc->integrity_tag_size, cc->iv_size);
	}
	memcpy(b->iv, b->org_iv, cc->iv_size);
	sg_init_table(sg, 4);
	sg_set_buf(&sg[0], &b->sector, sizeof(b->sector));
	sg_set_buf(&sg[1], b->org_iv, cc->iv_size);
	sg_set_page(&sg[2], page, cc->sector_size, offset);
	sg_set_buf(&sg[3], tuple, cc->integrity_tag_size);
	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, &wait);
	aead_request_set_ad(req, sizeof(b->sector) + cc->iv_size);
	aead_request_set_crypt(req, sg, sg, cc->sector_size + (encrypt ? 0 : cc->integrity_tag_size), b->iv);
	r = crypto_wait_req(encrypt ? crypto_aead_encrypt(req) : crypto_aead_decrypt(req), &wait);
	if (!r && encrypt && cc->integrity_tag_size + cc->iv_size != cc->tuple_size)
		memset(tuple + cc->integrity_tag_size + cc->iv_size, 0,
		       cc->tuple_size - cc->integrity_tag_size - cc->iv_size);
out:
	aead_request_free(req);
	kfree_sensitive(b);
	return r;
}

#include "piv-control.inc"

/* Ordinary owner reads (before native ownership): authenticated, bounded. */
struct piv_owner_work {
	struct work_struct work;
	struct piv_crypt *cc;
	struct bio *bio;
};

static void piv_owner_read(struct work_struct *work)
{
	struct piv_owner_work *w = container_of(work, struct piv_owner_work, work);
	struct piv_crypt *cc = w->cc;
	struct piv_control *p = cc->piv_control;
	struct bio *bio = w->bio;
	u32 bytes = bio->bi_iter.bi_size;
	u64 index = bio->bi_iter.bi_sector >> cc->sector_shift;
	u8 *buffer = NULL;
	unsigned int noio;
	int r = -EIO;

	mutex_lock(&p->lock);
	noio = memalloc_noio_save();
	if (p->live && !p->native && p->cc == cc) {
		buffer = kmalloc(bytes, GFP_NOIO);
		r = buffer ? piv_read_range(p, index, bytes / cc->sector_size, buffer, NULL) : -ENOMEM;
		if (!r)
			pn_copy_bio(bio, buffer, true);
	}
	memalloc_noio_restore(noio);
	mutex_unlock(&p->lock);
	kfree_sensitive(buffer);
	bio->bi_status = errno_to_blk_status(r);
	bio_endio(bio);
	kfree(w);
}

static int piv_crypt_map(struct dm_target *ti, struct bio *bio)
{
	struct piv_crypt *cc = ti->private;
	struct piv_owner_work *w;

	/* Native dual views bypass this private owner; prohibit cached raw I/O. */
	if (READ_ONCE(cc->piv_control->native))
		return DM_MAPIO_KILL;
	/* Only empty flushes reach the lower device; never ordinary writes. */
	if (bio_op(bio) == REQ_OP_WRITE && !bio->bi_iter.bi_size && (bio->bi_opf & REQ_PREFLUSH)) {
		bio_set_dev(bio, cc->dev->bdev);
		return DM_MAPIO_REMAPPED;
	}
	if (bio_op(bio) != REQ_OP_READ)
		return DM_MAPIO_KILL;
	bio->bi_iter.bi_sector = dm_target_offset(ti, bio->bi_iter.bi_sector);
	if ((bio->bi_iter.bi_sector & ((cc->sector_size >> SECTOR_SHIFT) - 1)) ||
	    (bio->bi_iter.bi_size & (cc->sector_size - 1)) || !bio->bi_iter.bi_size ||
	    bio->bi_iter.bi_size > PIV_READ_BYTES)
		return DM_MAPIO_KILL;
	w = kmalloc(sizeof(*w), GFP_NOWAIT | __GFP_NOWARN);
	if (!w)
		return DM_MAPIO_REQUEUE;
	INIT_WORK(&w->work, piv_owner_read);
	w->cc = cc;
	w->bio = bio;
	queue_work(piv_io_wq, &w->work);
	return DM_MAPIO_SUBMITTED;
}

static void piv_crypt_dtr(struct dm_target *ti)
{
	struct piv_crypt *cc = ti->private;

	if (!cc)
		return;
	piv_unregister(cc);
	if (!IS_ERR_OR_NULL(cc->tfm))
		crypto_free_aead(cc->tfm);
	if (cc->dev)
		dm_put_device(ti, cc->dev);
	kfree_sensitive(cc);
	ti->private = NULL;
}

/*
 * Table: <cipher> <hex key> <iv_offset=0> <device> <start=0> <#features>
 *        integrity:<16+iv>:aead [sector_size:<512|4096>] piv_control
 * This is the stock dm-crypt syntax for the pinned profiles with one extra
 * feature; anything else is rejected rather than interpreted.
 */
static int piv_crypt_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	const struct piv_profile *profile = NULL;
	struct blk_integrity *bi;
	struct piv_crypt *cc;
	unsigned long long value;
	unsigned int i, features, tag = 0;
	bool control = false;
	char dummy;
	int r;

	if (argc < 6) {
		ti->error = "Not enough arguments";
		return -EINVAL;
	}
	for (i = 0; i < ARRAY_SIZE(piv_profiles); i++)
		if (!strcmp(argv[0], piv_profiles[i].cipher_string))
			profile = &piv_profiles[i];
	if (!profile) {
		ti->error = "Unsupported cipher profile";
		return -EINVAL;
	}
	if (!(dm_table_get_mode(ti->table) & BLK_OPEN_WRITE)) {
		ti->error = "piv_control requires the tested writable-owner AEAD profile";
		return -EINVAL;
	}
	cc = kzalloc(sizeof(*cc), GFP_KERNEL);
	if (!cc)
		return -ENOMEM;
	ti->private = cc;
	strscpy(cc->cipher_string, profile->cipher_string, sizeof(cc->cipher_string));
	cc->key_size = profile->key_size;
	cc->iv_size = cc->integrity_iv_size = profile->iv_size;
	cc->integrity_tag_size = 16;
	cc->sector_size = 512;
	r = -EINVAL;
	if (strlen(argv[1]) != 2 * cc->key_size || hex2bin(cc->key, argv[1], cc->key_size)) {
		ti->error = "Invalid key (hex keys only)";
		goto bad;
	}
	if (sscanf(argv[2], "%llu%c", &value, &dummy) != 1 || value) {
		ti->error = "Unsupported IV offset";
		goto bad;
	}
	if (sscanf(argv[4], "%llu%c", &value, &dummy) != 1 || value) {
		ti->error = "Unsupported device offset";
		goto bad;
	}
	if (kstrtouint(argv[5], 10, &features) || features != argc - 6) {
		ti->error = "Invalid number of feature args";
		goto bad;
	}
	for (i = 6; i < argc; i++) {
		unsigned int size;

		if (!strcmp(argv[i], "piv_control") && !control)
			control = true;
		else if (sscanf(argv[i], "integrity:%u:aead%c", &size, &dummy) == 1 && !tag)
			tag = size;
		else if (sscanf(argv[i], "sector_size:%u%c", &size, &dummy) == 1 &&
			 (size == 512 || size == 4096))
			cc->sector_size = size;
		else {
			ti->error = "Unsupported feature";
			goto bad;
		}
	}
	if (!control || tag != cc->integrity_tag_size + cc->iv_size) {
		ti->error = "piv_control and integrity:<16+iv>:aead are required";
		goto bad;
	}
	cc->sector_shift = __ffs(cc->sector_size) - SECTOR_SHIFT;
	if (ti->len & ((cc->sector_size >> SECTOR_SHIFT) - 1)) {
		ti->error = "Device size is not a multiple of the sector size";
		goto bad;
	}
	r = dm_get_device(ti, argv[3], dm_table_get_mode(ti->table), &cc->dev);
	if (r) {
		ti->error = "Device lookup failed";
		goto bad;
	}
	r = -EINVAL;
	bi = blk_get_integrity(cc->dev->bdev->bd_disk);
	if (!bi || bi->csum_type != BLK_INTEGRITY_CSUM_NONE || bi->tuple_size != tag ||
	    1U << bi->interval_exp != cc->sector_size) {
		ti->error = "Lower integrity profile does not match";
		goto bad;
	}
	cc->tuple_size = bi->tuple_size;
	cc->tfm = crypto_alloc_aead(profile->algorithm, 0, 0);
	if (IS_ERR(cc->tfm)) {
		r = PTR_ERR(cc->tfm);
		ti->error = "Cannot allocate AEAD transform";
		goto bad;
	}
	r = crypto_aead_setkey(cc->tfm, cc->key, cc->key_size);
	/* The transform holds the key schedule; keep no other copy. */
	memzero_explicit(cc->key, sizeof(cc->key));
	if (!r)
		r = crypto_aead_setauthsize(cc->tfm, cc->integrity_tag_size);
	if (r || crypto_aead_ivsize(cc->tfm) != cc->iv_size) {
		r = r ?: -EINVAL;
		ti->error = "AEAD key/tag/IV size rejected";
		goto bad;
	}
	set_bit(PIV_KEY_VALID, &cc->flags);
	ti->num_flush_bios = 1;
	r = dm_set_target_max_io_len(ti, PIV_READ_BYTES >> SECTOR_SHIFT);
	if (r)
		goto bad;
	r = piv_register(cc, ti);
	if (r)
		goto bad;
	return 0;
bad:
	piv_crypt_dtr(ti);
	return r;
}

static void piv_crypt_status(struct dm_target *ti, status_type_t type,
			     unsigned int status_flags, char *result, unsigned int maxlen)
{
	struct piv_crypt *cc = ti->private;
	unsigned int sz = 0;

	switch (type) {
	case STATUSTYPE_INFO:
		result[0] = '\0';
		break;
	case STATUSTYPE_TABLE:
		/* Never emit key material; this table is not meant to be reloaded. */
		DMEMIT("%s - %llu %s %llu", cc->cipher_string, (unsigned long long)cc->iv_offset,
		       cc->dev->name, (unsigned long long)cc->start);
		if (cc->sector_size != 512)
			DMEMIT(" 3 piv_control integrity:%u:aead sector_size:%u",
			       cc->tuple_size, cc->sector_size);
		else
			DMEMIT(" 2 piv_control integrity:%u:aead", cc->tuple_size);
		break;
	case STATUSTYPE_IMA:
		DMEMIT_TARGET_NAME_VERSION(ti->type);
		DMEMIT(",cipher_string=%s,sector_size=%u;", cc->cipher_string, cc->sector_size);
		break;
	}
}

static void piv_crypt_postsuspend(struct dm_target *ti)
{
	struct piv_crypt *cc = ti->private;

	set_bit(PIV_SUSPENDED, &cc->flags);
}

static void piv_crypt_resume(struct dm_target *ti)
{
	struct piv_crypt *cc = ti->private;

	clear_bit(PIV_SUSPENDED, &cc->flags);
	piv_unblock(ti);
}

/* Only "key wipe", as dm-crypt allows it: while suspended and with no active
 * transaction or native owner. Afterwards resume and controls stay refused.
 */
static int piv_crypt_message(struct dm_target *ti, unsigned int argc, char **argv,
			     char *result, unsigned int maxlen)
{
	struct piv_crypt *cc = ti->private;
	struct piv_control *p = cc->piv_control;
	int r;

	if (argc != 2 || strcasecmp(argv[0], "key") || strcasecmp(argv[1], "wipe"))
		return -EINVAL;
	mutex_lock(&p->lock);
	if (p->transaction || p->resuming || p->native || !test_bit(PIV_SUSPENDED, &cc->flags)) {
		r = -EBUSY;
	} else {
		clear_bit(PIV_KEY_VALID, &cc->flags);
		get_random_bytes(cc->key, cc->key_size);
		r = crypto_aead_setkey(cc->tfm, cc->key, cc->key_size);
		memzero_explicit(cc->key, sizeof(cc->key));
	}
	mutex_unlock(&p->lock);
	return r;
}

static int piv_crypt_iterate(struct dm_target *ti, iterate_devices_callout_fn fn, void *data)
{
	struct piv_crypt *cc = ti->private;

	return fn(ti, cc->dev, cc->start, ti->len, data);
}

static void piv_crypt_hints(struct dm_target *ti, struct queue_limits *limits)
{
	struct piv_crypt *cc = ti->private;

	limits->logical_block_size = max_t(unsigned int, limits->logical_block_size, cc->sector_size);
	limits->physical_block_size = max_t(unsigned int, limits->physical_block_size, cc->sector_size);
	limits->io_min = max_t(unsigned int, limits->io_min, cc->sector_size);
	limits->dma_alignment = limits->logical_block_size - 1;
}

static struct target_type piv_crypt_target = {
	.name = "piv-crypt",
	.version = {2, 0, 0},
	.module = THIS_MODULE,
	.ctr = piv_crypt_ctr,
	.dtr = piv_crypt_dtr,
	.map = piv_crypt_map,
	.status = piv_crypt_status,
	.presuspend = piv_presuspend,
	.presuspend_undo = piv_unblock,
	.postsuspend = piv_crypt_postsuspend,
	.preresume = piv_preresume,
	.resume = piv_crypt_resume,
	.message = piv_crypt_message,
	.iterate_devices = piv_crypt_iterate,
	.io_hints = piv_crypt_hints,
};

static int __init piv_module_init(void)
{
	int r = -ENOMEM;

	pn_wq = alloc_ordered_workqueue("piv-native", WQ_MEM_RECLAIM);
	piv_io_wq = alloc_workqueue("kpiv_io", WQ_MEM_RECLAIM | WQ_UNBOUND, 0);
	if (!pn_wq || !piv_io_wq)
		goto free_wq;
	r = dm_register_target(&piv_crypt_target);
	if (r)
		goto free_wq;
	r = dm_register_target(&piv_view_target);
	if (!r)
		return 0;
	dm_unregister_target(&piv_crypt_target);
free_wq:
	if (piv_io_wq)
		destroy_workqueue(piv_io_wq);
	if (pn_wq)
		destroy_workqueue(pn_wq);
	return r;
}

static void __exit piv_module_exit(void)
{
	dm_unregister_target(&piv_view_target);
	dm_unregister_target(&piv_crypt_target);
	destroy_workqueue(piv_io_wq);
	destroy_workqueue(pn_wq);
}

module_init(piv_module_init);
module_exit(piv_module_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION(DM_NAME " persistent-IV paired-volume targets (standalone AEAD sectors)");
MODULE_ALIAS("dm-piv-crypt");
MODULE_ALIAS("dm-piv-view");
