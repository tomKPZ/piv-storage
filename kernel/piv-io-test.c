// SPDX-License-Identifier: GPL-2.0-only
/* Disposable guest test only: submit exact flags to the two public views.
 * Never link this into dm-piv. No keys, arbitrary paths or arbitrary offsets.
 */
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/highmem.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>

static DEFINE_MUTEX(test_lock);

static int test_bio(struct block_device *bdev, struct page *page, blk_opf_t op)
{
	struct bio *bio = bio_alloc(bdev, 1, op, GFP_KERNEL);
	int r;
	if (!bio)
		return -ENOMEM;
	bio->bi_iter.bi_sector = 0;
	if (bio_add_page(bio, page, 512, 0) != 512) {
		bio_put(bio);
		return -EINVAL;
	}
	r = submit_bio_wait(bio);
	bio_put(bio);
	return r;
}

static ssize_t test_write(struct file *unused, const char __user *data,
			  size_t count, loff_t *position)
{
	u32 args[2]; /* role: decoy=0 / hidden=1; mode: plain/FUA/PREFLUSH+FUA/flush */
	struct file *file;
	struct page *page = NULL;
	struct block_device *bdev;
	int r;
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (count != sizeof(args) || copy_from_user(args, data, sizeof(args)))
		return -EINVAL;
	if (args[0] > 1 || args[1] > 3)
		return -EINVAL;
	mutex_lock(&test_lock);
	file = filp_open(args[0] ? "/dev/mapper/piv-native-hidden" :
			 "/dev/mapper/piv-native-decoy", O_RDWR | O_LARGEFILE, 0);
	if (IS_ERR(file)) { r = PTR_ERR(file); goto unlock; }
	if (!S_ISBLK(file_inode(file)->i_mode)) { r = -EINVAL; goto close; }
	bdev = file_bdev(file);
	if (args[1] == 3) { r = blkdev_issue_flush(bdev); goto close; }
	page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!page) { r = -ENOMEM; goto close; }
	r = test_bio(bdev, page, REQ_OP_READ);
	if (!r)
		r = test_bio(bdev, page, REQ_OP_WRITE |
			(args[1] ? REQ_FUA : 0) | (args[1] == 2 ? REQ_PREFLUSH : 0));
close:
	if (page) {
		memzero_explicit(page_address(page), PAGE_SIZE);
		__free_page(page);
	}
	fput(file);
unlock:
	mutex_unlock(&test_lock);
	return r ? r : count;
}

static const struct file_operations test_ops = {
	.owner = THIS_MODULE, .open = nonseekable_open, .write = test_write,
};
static struct miscdevice test_device = {
	.minor = MISC_DYNAMIC_MINOR, .name = "piv-io-test", .fops = &test_ops, .mode = 0600,
};
static int __init test_init(void) { return misc_register(&test_device); }
static void __exit test_exit(void) { misc_deregister(&test_device); }
module_init(test_init);
module_exit(test_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Disposable paired-view exact-bio-flags test helper");
