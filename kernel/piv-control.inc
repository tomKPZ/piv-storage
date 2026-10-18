/* SPDX-License-Identifier: GPL-2.0-only */
/* Included after crypt_config: immutable profile snapshot, no dangling cc pointer.
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

static long piv_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct piv_control *p = file->private_data;
	long ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (cmd != PIV_QUERY)
		return -ENOTTY;
	mutex_lock(&p->lock);
	ret = !p->live ? -ENODEV :
		copy_to_user((void __user *)arg, &p->profile,
			     sizeof(p->profile)) ? -EFAULT : 0;
	mutex_unlock(&p->lock);
	return ret;
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
	mutex_unlock(&p->lock);
	misc_deregister(&p->misc);
	kref_put(&p->refs, piv_free);
	cc->piv_control = NULL;
}
