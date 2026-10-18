/* SPDX-License-Identifier: GPL-2.0-only */
/* Included after native AEAD helpers. cc is borrowed only while lock is held.
 * misc_open serializes our open callback with misc_deregister via misc_mtx.
 * A registration reference survives deregistration; each open takes its own.
 * Open fds pin THIS_MODULE and remain valid (ENODEV) after target destruction.
 */
static atomic64_t piv_generation = ATOMIC64_INIT(0);
struct piv_control {
	struct miscdevice misc;
	struct kref refs;
	struct mutex lock;
	bool live;
	bool blocked;
	struct crypt_config *cc;
	struct piv_query profile;
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
	kref_put(&p->refs, piv_free);
	return 0;
}

/* Caller holds p->lock across lower I/O and crypto; dtr/presuspend drain it.
 * Read through the SAME lower integrity target, carrying one complete tuple.
 * Decrypt only into a private page and return no plaintext, including on error.
 */
static int piv_read_iv(struct piv_control *p, struct piv_read_iv *out)
{
	struct crypt_config *cc = p->cc;
	struct dm_crypt_io *io = NULL;
	struct aead_request *req = NULL;
	struct page *page = NULL;
	struct bio *bio = NULL;
	struct bvec_iter saved;
	DECLARE_CRYPTO_WAIT(wait);
	int ret = -ENOMEM;

	if (out->version != 1 || out->size != sizeof(*out) ||
	    memchr_inv(out->iv, 0, sizeof(out->iv)) ||
	    memchr_inv(out->reserved, 0, sizeof(out->reserved)))
		return -EINVAL;
	if (out->generation != p->profile.generation)
		return -ESTALE;
	if (out->sector >= p->profile.sectors)
		return -ERANGE;
	if (p->blocked || !test_bit(DM_CRYPT_KEY_VALID, &cc->flags))
		return -EBUSY;

	io = kzalloc(sizeof(*io), GFP_NOIO);
	page = alloc_page(GFP_NOIO | __GFP_ZERO);
	if (!io || !page)
		goto done;
	io->cc = cc;
	io->sector = out->sector << cc->sector_shift;
	io->integrity_metadata = kzalloc(cc->tuple_size, GFP_NOIO);
	if (!io->integrity_metadata)
		goto done;
	bio = bio_alloc(cc->dev->bdev, 1, REQ_OP_READ, GFP_NOIO);
	if (!bio)
		goto done;
	bio->bi_iter.bi_sector = cc->start + io->sector;
	if (bio_add_page(bio, page, cc->sector_size, 0) != cc->sector_size)
		goto done;
	ret = dm_crypt_integrity_io_alloc(io, bio);
	if (ret)
		goto done;
	saved = bio->bi_iter;
	ret = submit_bio_wait(bio);
	if (ret)
		goto done;
	/* Lower drivers may advance the bio; crypto iterates the original sector. */
	bio->bi_iter = saved;
	crypt_convert_init(cc, &io->ctx, bio, bio, io->sector);
	req = mempool_alloc(&cc->req_pool, GFP_NOIO);
	aead_request_set_tfm(req, any_tfm_aead(cc));
	aead_request_set_callback(req,
		CRYPTO_TFM_REQ_MAY_BACKLOG,
		crypto_req_done, &wait);
	ret = crypto_wait_req(crypt_convert_block_aead(cc, &io->ctx, req, 0), &wait);
	if (!ret)
		memcpy(out->iv, io->integrity_metadata + cc->integrity_tag_size,
		       sizeof(out->iv));
done:
	if (req)
		mempool_free(req, &cc->req_pool);
	if (bio)
		bio_put(bio);
	if (page) {
		memzero_explicit(page_address(page), PAGE_SIZE);
		__free_page(page);
	}
	if (io) {
		kfree_sensitive(io->integrity_metadata);
		kfree(io);
	}
	return ret;
}

static long piv_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct piv_control *p = file->private_data;
	struct piv_read_iv read;
	struct piv_query profile;
	long ret = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (cmd != PIV_QUERY && cmd != PIV_READ_IV)
		return -ENOTTY;
	if (cmd == PIV_READ_IV &&
	    copy_from_user(&read, (void __user *)arg, sizeof(read)))
		return -EFAULT;
	mutex_lock(&p->lock);
	if (!p->live)
		ret = -ENODEV;
	else if (cmd == PIV_READ_IV) {
		unsigned int noio = memalloc_noio_save();

		ret = piv_read_iv(p, &read);
		memalloc_noio_restore(noio);
	}
	else
		profile = p->profile;
	mutex_unlock(&p->lock);
	/* Never fault userspace pages while holding the target/lifecycle mutex. */
	if (!ret) {
		if (cmd == PIV_READ_IV)
			ret = copy_to_user((void __user *)arg, &read, sizeof(read)) ? -EFAULT : 0;
		else
			ret = copy_to_user((void __user *)arg, &profile, sizeof(profile)) ? -EFAULT : 0;
	}
	return ret;
}

/* presuspend runs before upper I/O drains or lower tables are suspended. */
static void piv_presuspend(struct dm_target *ti)
{
	struct crypt_config *cc = ti->private;
	struct piv_control *p = cc->piv_control;
	if (!p)
		return;
	mutex_lock(&p->lock);
	p->blocked = true;
	mutex_unlock(&p->lock);
}

static void piv_unblock(struct dm_target *ti)
{
	struct crypt_config *cc = ti->private;
	struct piv_control *p = cc->piv_control;
	if (!p)
		return;
	mutex_lock(&p->lock);
	p->blocked = false;
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

static int piv_register(struct crypt_config *cc, struct dm_target *ti)
{
	struct piv_control *p;
	int ret;

	if (!cc->piv_enabled)
		return 0;
	/* Pin the existing tested crypto profile; this is not a general API. */
	if (!crypt_integrity_aead(cc) || cc->iv_gen_ops != &crypt_iv_random_ops ||
	    strcmp(cc->cipher_string, "capi:gcm(aes)-random") ||
	    cc->key_size != 32 || cc->sector_size != 4096 ||
	    cc->iv_size != 12 || cc->integrity_iv_size != 12 ||
	    cc->integrity_tag_size != 16 || cc->tuple_size != 28 ||
	    cc->iv_offset || cc->start ||
	    test_bit(CRYPT_IV_LARGE_SECTORS, &cc->cipher_flags) ||
	    !(dm_table_get_mode(ti->table) & BLK_OPEN_WRITE)) {
		ti->error = "piv_control requires the tested writable-owner GCM profile";
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
		.version = 1, .size = sizeof(struct piv_query),
		.generation = atomic64_inc_return(&piv_generation),
		.sectors = ti->len >> cc->sector_shift,
		.sector_size = cc->sector_size, .iv_size = cc->iv_size,
		.tag_size = cc->integrity_tag_size, .tuple_size = cc->tuple_size,
		.flags = PIV_QUERY_LOWER_WRITE | PIV_QUERY_PRIMARY_FILTER,
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
	return 0;
}

static void piv_unregister(struct crypt_config *cc)
{
	struct piv_control *p = cc->piv_control;
	if (!p)
		return;
	mutex_lock(&p->lock);
	p->live = false;
	p->blocked = true;
	p->cc = NULL;
	mutex_unlock(&p->lock);
	misc_deregister(&p->misc);
	kref_put(&p->refs, piv_free);
	cc->piv_control = NULL;
}
