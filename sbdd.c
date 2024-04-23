#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/bio.h>
#include <linux/bvec.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/wait.h>
#include <linux/stat.h>
#include <linux/slab.h>
#include <linux/numa.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/moduleparam.h>
#include <linux/spinlock_types.h>

#define SBDD_SECTOR_SHIFT      9
#define SBDD_SECTOR_SIZE       (1 << SBDD_SECTOR_SHIFT)
#define SBDD_MIB_SECTORS       (1 << (20 - SBDD_SECTOR_SHIFT))
#define SBDD_NAME              "sbdd"

#define MAX_TARGET_DEVICES     2

struct sbdd {
	wait_queue_head_t       exitwait;
	spinlock_t              datalock;
	atomic_t                deleting;
	atomic_t                refs_cnt;
	sector_t                capacity;
	u8                      *data;
	struct gendisk          *gd;
	struct request_queue    *q;
	int                     raid_type;
	struct block_device     *target_devices[MAX_TARGET_DEVICES];               // Target devices
	char                    target_device_paths[MAX_TARGET_DEVICES][PATH_MAX]; // Paths to the target devices
};

static struct sbdd      __sbdd;
static struct bio_set   __sbdd_bio_set;
static int              __sbdd_major = 0;
static unsigned long    __sbdd_capacity_mib = 100;

enum {
	RAID0,
	RAID1
};

static ssize_t raid_type_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	/* TBD */
	/* Should list all suppoted raid types and underline currently active one */
	return 0;
}

static ssize_t raid_type_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t len)
{
    /* TBD */
	return 0;
}

static ssize_t target_device_path_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	char *str = buf;
	int i;

    for (i = 0; i < MAX_TARGET_DEVICES; ++i)
        str += sprintf(str, "%s\n", __sbdd.target_device_paths[i]);

    return str - buf;
}

static ssize_t target_device_path_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t len)
{
	static char target_device_paths[MAX_TARGET_DEVICES][PATH_MAX];
    struct block_device *target_devices[MAX_TARGET_DEVICES];
    sector_t capacity;
	char *path_buf, *token;
	const char delimiters[] = " ,\t\n";
    int i, num_devices = 0;

	if (len >= PATH_MAX * MAX_TARGET_DEVICES)
        return -EINVAL;

	// Release previously set target devices
    for (i = 0; i < MAX_TARGET_DEVICES; ++i) {
        if (__sbdd.target_devices[i]) {
            blkdev_put(__sbdd.target_devices[i], FMODE_READ|FMODE_WRITE);
            __sbdd.target_devices[i] = NULL;
            __sbdd.target_device_paths[i][0] = '\0';
			target_device_paths[i][0] = '\0';
        }
    }

	// Copy and parse the comma-separated list of target device paths
	path_buf = kstrndup(buf, len, GFP_KERNEL);
    token = strsep(&path_buf, delimiters);

	while (token != NULL && strlen(token) > 0 && num_devices < MAX_TARGET_DEVICES) {
    	if (strlen(token) < PATH_MAX) {
        	// Copy the target device path
        	strcpy(target_device_paths[num_devices], token);
        	num_devices++;
    	} else {
        	pr_err("Invalid target device path: %s\n", token);
        	kfree(path_buf);
        	return -EINVAL;
    	}
    	token = strsep(&path_buf, delimiters);
    }
    kfree(path_buf);
	
	// Open the new target devices
    for (i = 0; i < num_devices; ++i) {
        target_devices[i] = blkdev_get_by_path(target_device_paths[i], FMODE_READ|FMODE_WRITE, THIS_MODULE);
        if (IS_ERR(target_devices[i])) {
            pr_err("Failed to open target block device %s, %ld\n", target_device_paths[i], PTR_ERR(target_devices[i]));
        } else {
            strcpy(__sbdd.target_device_paths[i], target_device_paths[i]);
            __sbdd.target_devices[i] = target_devices[i];
            capacity = get_capacity(__sbdd.target_devices[i]->bd_disk);
            pr_debug("Set target_device_path[%d] = %s as target block device, capacity = %llu\n", i, __sbdd.target_device_paths[i], capacity);
        }
    }

    return len;
}

static DEVICE_ATTR_RW(raid_type);
static DEVICE_ATTR_RW(target_device_path);

static struct attribute *sbdd_disk_attrs[] = {
		&dev_attr_raid_type.attr,
		&dev_attr_target_device_path.attr,
        NULL,
};

static const struct attribute_group sbdd_disk_attr_group = {
        .attrs = sbdd_disk_attrs,
};

static void sbdd_forward_bio(struct bio *bio)
{
	struct bio *clone_bio;
	sector_t sector_offset = 0;
	sector_t target_sector;
    int i;

	// Clone the original BIO
	clone_bio = bio_clone_fast(bio, GFP_KERNEL, &__sbdd_bio_set);
    if (!clone_bio) {
        pr_err("Failed to clone bio\n");
        return;
    }

    if (__sbdd.raid_type == RAID1) {
    	for (i = 0; i < MAX_TARGET_DEVICES; ++i) {
        	if (__sbdd.target_devices[i]) {
            	// Set the target device
            	bio_set_dev(clone_bio, __sbdd.target_devices[i]);

            	// Submit the cloned BIO to the target device
            	pr_debug("Submit BIO to target device %s\n", __sbdd.target_device_paths[i]);
            	submit_bio(clone_bio);
        	}
    	}
	} else if (__sbdd.raid_type == RAID0) {
		for (i = 0; i < MAX_TARGET_DEVICES; ++i) {
			if (__sbdd.target_devices[i]) {
				// Calculate the sector offset for the target device
				target_sector = sector_offset + bio->bi_iter.bi_sector;

				// Set the target device and sector
				bio_set_dev(clone_bio, __sbdd.target_devices[i]);
				clone_bio->bi_iter.bi_sector = target_sector;

				// Submit the cloned BIO to the target device
				pr_debug("Submit BIO to target device %s (sector %llu)\n", __sbdd.target_device_paths[i], target_sector);
				submit_bio(clone_bio);

				// Update the sector offset for the next target device
				sector_offset += bio->bi_iter.bi_size >> 9; // Convert size in bytes to sectors
			}
		}
	} else {
		pr_err("unsupported RAID type...\n");
	}
}

static sector_t sbdd_xfer(struct bio_vec* bvec, sector_t pos, int dir)
{
	void *buff = kmap_atomic(bvec->bv_page) + bvec->bv_offset;
	sector_t len = bvec->bv_len >> SBDD_SECTOR_SHIFT;
	size_t offset;
	size_t nbytes;

	if (pos + len > __sbdd.capacity)
		len = __sbdd.capacity - pos;

	offset = pos << SBDD_SECTOR_SHIFT;
	nbytes = len << SBDD_SECTOR_SHIFT;

	spin_lock(&__sbdd.datalock);

    if (dir)
		memcpy(__sbdd.data + offset, buff, nbytes);
	else
		memcpy(buff, __sbdd.data + offset, nbytes);

	spin_unlock(&__sbdd.datalock);

	pr_debug("pos=%6llu len=%4llu %s\n", pos, len, dir ? "written" : "read");

	kunmap_atomic(buff);
	return len;
}

static void sbdd_xfer_bio(struct bio *bio)
{
	struct bvec_iter iter;
	struct bio_vec bvec;
	int dir = bio_data_dir(bio);
	sector_t pos = bio->bi_iter.bi_sector;
	int i, target_device_set_flag = 0;

	// Check if at least one target device is set
	for (i = 0; i < MAX_TARGET_DEVICES; ++i) {
		if (__sbdd.target_devices[i]) {
			target_device_set_flag = 1;
			break;
		}
	}
	if (target_device_set_flag) {
		sbdd_forward_bio(bio);
	} else {
		bio_for_each_segment(bvec, bio, iter)
			pos += sbdd_xfer(&bvec, pos, dir);
	}
}

static blk_qc_t sbdd_make_request(struct request_queue *q, struct bio *bio)
{
	if (atomic_read(&__sbdd.deleting)) {
		bio_io_error(bio);
		return BLK_STS_IOERR;
	}

	if (!atomic_inc_not_zero(&__sbdd.refs_cnt)) {
		bio_io_error(bio);
		return BLK_STS_IOERR;
	}

	sbdd_xfer_bio(bio);
	bio_endio(bio);

	if (atomic_dec_and_test(&__sbdd.refs_cnt))
		wake_up(&__sbdd.exitwait);

	return BLK_STS_OK;
}

/*
There are no read or write operations. These operations are performed by
the request() function associated with the request queue of the disk.
*/
static struct block_device_operations const __sbdd_bdev_ops = {
	.owner = THIS_MODULE,
};

static int sbdd_create(void)
{
	int ret = 0;
	/*
	This call is somewhat redundant, but used anyways by tradition.
	The number is to be displayed in /proc/devices (0 for auto).
	*/
	pr_info("registering blkdev\n");
	__sbdd_major = register_blkdev(0, SBDD_NAME);
	if (__sbdd_major < 0) {
		pr_err("call register_blkdev() failed with %d\n", __sbdd_major);
		return -EBUSY;
	}

	memset(&__sbdd, 0, sizeof(struct sbdd));
	__sbdd.capacity = (sector_t)__sbdd_capacity_mib * SBDD_MIB_SECTORS;

	pr_info("allocating data\n");
	__sbdd.data = vzalloc(__sbdd.capacity << SBDD_SECTOR_SHIFT);
	if (!__sbdd.data) {
		pr_err("unable to alloc data\n");
		unregister_blkdev(__sbdd_major, SBDD_NAME);
		return -ENOMEM;
	}

    pr_info("initializing bio set\n");
	if (bioset_init(&__sbdd_bio_set, BIO_POOL_SIZE, 0, BIOSET_NEED_BVECS)) {
		pr_err("bioset_init failed\n");
		vfree(__sbdd.data);
		unregister_blkdev(__sbdd_major, SBDD_NAME);
		return -ENOMEM;
	}

	spin_lock_init(&__sbdd.datalock);
	init_waitqueue_head(&__sbdd.exitwait);

	pr_info("allocating queue\n");
	__sbdd.q = blk_alloc_queue(GFP_KERNEL);
	if (!__sbdd.q) {
		pr_err("call blk_alloc_queue() failed\n");
		vfree(__sbdd.data);
		unregister_blkdev(__sbdd_major, SBDD_NAME);
		return -EINVAL;
	}
	blk_queue_make_request(__sbdd.q, sbdd_make_request);

	/* Configure queue */
	blk_queue_logical_block_size(__sbdd.q, SBDD_SECTOR_SIZE);

	/* A disk must have at least one minor */
	pr_info("allocating disk\n");
	__sbdd.gd = alloc_disk(1);

    memset(__sbdd.target_devices, 0, sizeof(__sbdd.target_devices));
	/* Set default RAID type */
	__sbdd.raid_type == RAID1;

	/* Configure gendisk */
	__sbdd.gd->queue = __sbdd.q;
	__sbdd.gd->major = __sbdd_major;
	__sbdd.gd->first_minor = 0;
	__sbdd.gd->fops = &__sbdd_bdev_ops;

	/* Represents name in /proc/partitions and /sys/block */
	scnprintf(__sbdd.gd->disk_name, DISK_NAME_LEN, SBDD_NAME);
	set_capacity(__sbdd.gd, __sbdd.capacity);
	atomic_set(&__sbdd.refs_cnt, 1);

	/*
	Allocating gd does not make it available, add_disk() required.
	After this call, gd methods can be called at any time. Should not be
	called before the driver is fully initialized and ready to process reqs.
	*/
	pr_info("adding disk\n");
	add_disk(__sbdd.gd);
	
	/* Create sysfs interface */
	ret = sysfs_create_group(&disk_to_dev(__sbdd.gd)->kobj,	&sbdd_disk_attr_group);
	if (ret < 0) {
		vfree(__sbdd.data);
		unregister_blkdev(__sbdd_major, SBDD_NAME);
		pr_err("Error creating sysfs group for sbdd device\n");
	}

	return ret;
}

static void sbdd_delete(void)
{
	int i;
	atomic_set(&__sbdd.deleting, 1);
	atomic_dec(&__sbdd.refs_cnt);
	wait_event(__sbdd.exitwait, !atomic_read(&__sbdd.refs_cnt));

    /* remove sysfs interface */
    sysfs_remove_group(&disk_to_dev(__sbdd.gd)->kobj, &sbdd_disk_attr_group);

    /* Release target devices */
	for (i = 0; i < MAX_TARGET_DEVICES; ++i)
        if (__sbdd.target_devices[i])
            blkdev_put(__sbdd.target_devices[i], FMODE_READ|FMODE_WRITE);
	
	/* gd will be removed only after the last reference put */
	if (__sbdd.gd) {
		pr_info("deleting disk\n");
		del_gendisk(__sbdd.gd);
	}

	if (__sbdd.q) {
		pr_info("cleaning up queue\n");
		blk_cleanup_queue(__sbdd.q);
	}

	if (__sbdd.gd)
		put_disk(__sbdd.gd);

	if (__sbdd.data) {
		pr_info("freeing data\n");
		vfree(__sbdd.data);
	}

	memset(&__sbdd, 0, sizeof(struct sbdd));

	if (__sbdd_major > 0) {
		pr_info("unregistering blkdev\n");
		unregister_blkdev(__sbdd_major, SBDD_NAME);
		__sbdd_major = 0;
	}
}

/*
Note __init is for the kernel to drop this function after
initialization complete making its memory available for other uses.
There is also __initdata note, same but used for variables.
*/
static int __init sbdd_init(void)
{
	int ret = 0;

	pr_info("starting initialization...\n");
	ret = sbdd_create();

	if (ret) {
		pr_warn("initialization failed\n");
		sbdd_delete();
	} else {
		pr_info("initialization complete\n");
	}

	return ret;
}

/*
Note __exit is for the compiler to place this code in a special ELF section.
Sometimes such functions are simply discarded (e.g. when module is built
directly into the kernel). There is also __exitdata note.
*/
static void __exit sbdd_exit(void)
{
	pr_info("exiting...\n");
	sbdd_delete();
	pr_info("exiting complete\n");
}

/* Called on module loading. Is mandatory. */
module_init(sbdd_init);

/* Called on module unloading. Unloading module is not allowed without it. */
module_exit(sbdd_exit);

/* Set desired capacity with insmod */
module_param_named(capacity_mib, __sbdd_capacity_mib, ulong, S_IRUGO);

/* Note for the kernel: a free license module. A warning will be outputted without it. */
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Simple Block Device Driver");
