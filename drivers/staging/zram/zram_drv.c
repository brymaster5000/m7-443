/*
 * Compressed RAM block device
 *
 * Copyright (C) 2008, 2009, 2010  Nitin Gupta
 *
 * This code is released using a dual license strategy: BSD/GPL
 * You can choose the licence that better fits your requirements.
 *
 * Released under the terms of 3-clause BSD License
 * Released under the terms of GNU General Public License Version 2.0
 *
 * Project home: http://compcache.googlecode.com
 */

#define KMSG_COMPONENT "zram"
#define pr_fmt(fmt) KMSG_COMPONENT ": " fmt

#ifdef CONFIG_ZRAM_DEBUG
#define DEBUG
#endif

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bio.h>
#include <linux/bitops.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>
#include <linux/device.h>
#include <linux/genhd.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <linux/cpu.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/ratelimit.h>

#include "zram_drv.h"

#define ZRAM_COMPRESSOR_DEFAULT "lz4"

/* Globals */
static int zram_major;
static struct zram *zram_devices;

/* Module params (documentation at end) */
static unsigned int num_devices = 1;

static unsigned int num_devices = 1;

static inline struct zram *dev_to_zram(struct device *dev)
{
	return (struct zram *)dev_to_disk(dev)->private_data;
}

static ssize_t disksize_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct zram *zram = dev_to_zram(dev);

	return sprintf(buf, "%llu\n", zram->disksize);
}

static ssize_t initstate_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct zram *zram = dev_to_zram(dev);

	return sprintf(buf, "%u\n", zram->init_done);
}

static ssize_t num_reads_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct zram *zram = dev_to_zram(dev);

	return sprintf(buf, "%llu\n",
			(u64)atomic64_read(&zram->stats.num_reads));
}

static ssize_t num_writes_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct zram *zram = dev_to_zram(dev);

	return sprintf(buf, "%llu\n",
			(u64)atomic64_read(&zram->stats.num_writes));
}

static ssize_t invalid_io_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct zram *zram = dev_to_zram(dev);

	return sprintf(buf, "%llu\n",
			(u64)atomic64_read(&zram->stats.invalid_io));
}

/* Cryptographic API features */
static char *zram_compressor = ZRAM_COMPRESSOR_DEFAULT;
static struct crypto_comp * __percpu *zram_comp_pcpu_tfms;

enum comp_op {
	ZRAM_COMPOP_COMPRESS,
	ZRAM_COMPOP_DECOMPRESS
};

static int zram_comp_op(enum comp_op op, const u8 *src, unsigned int slen,
			u8 *dst, unsigned int *dlen)
{
	struct crypto_comp *tfm;
	int ret;

	tfm = *per_cpu_ptr(zram_comp_pcpu_tfms, get_cpu());
	switch (op) {
	case ZRAM_COMPOP_COMPRESS:
		ret = crypto_comp_compress(tfm, src, slen, dst, dlen);
		break;
	case ZRAM_COMPOP_DECOMPRESS:
		ret = crypto_comp_decompress(tfm, src, slen, dst, dlen);
		break;
	default:
		ret = -EINVAL;
	}
	put_cpu();

	return ret;
}

static int __init zram_comp_init(void)
{
	int ret;
	ret = crypto_has_comp(zram_compressor, 0, 0);
	if (!ret) {
		pr_info("%s is not available\n", zram_compressor);
		zram_compressor = ZRAM_COMPRESSOR_DEFAULT;
		ret = crypto_has_comp(zram_compressor, 0, 0);
		if (!ret)
			return -ENODEV;
	}
	pr_info("using %s compressor\n", zram_compressor);

	/* alloc percpu transforms */
	zram_comp_pcpu_tfms = alloc_percpu(struct crypto_comp *);
	if (!zram_comp_pcpu_tfms)
		return -ENOMEM;

	return 0;
}

static inline void zram_comp_exit(void)
{
	/* free percpu transforms */
	if (zram_comp_pcpu_tfms)
		free_percpu(zram_comp_pcpu_tfms);
}


/* Crypto API features: percpu code */
#define ZRAM_DSTMEM_ORDER 1
static DEFINE_PER_CPU(u8 *, zram_dstmem);

static int zram_comp_cpu_up(int cpu)
{
	struct crypto_comp *tfm;

	tfm = crypto_alloc_comp(zram_compressor, 0, 0);
	if (IS_ERR(tfm))
		return NOTIFY_BAD;
	*per_cpu_ptr(zram_comp_pcpu_tfms, cpu) = tfm;
	return NOTIFY_OK;
}

static void zram_comp_cpu_down(int cpu)
{
	struct crypto_comp *tfm;

	tfm = *per_cpu_ptr(zram_comp_pcpu_tfms, cpu);
	crypto_free_comp(tfm);
	*per_cpu_ptr(zram_comp_pcpu_tfms, cpu) = NULL;
}

static int zram_cpu_notifier(struct notifier_block *nb,
				unsigned long action, void *pcpu)
{
	int ret;
	int cpu = (long) pcpu;

	switch (action) {
	case CPU_UP_PREPARE:
		ret = zram_comp_cpu_up(cpu);
		if (ret != NOTIFY_OK) {
			pr_err("zram: can't allocate compressor xform\n");
			return ret;
		}
		per_cpu(zram_dstmem, cpu) = (void *)__get_free_pages(
			GFP_KERNEL | __GFP_REPEAT, ZRAM_DSTMEM_ORDER);
		break;
	case CPU_DEAD:
	case CPU_UP_CANCELED:
		zram_comp_cpu_down(cpu);
		free_pages((unsigned long) per_cpu(zram_dstmem, cpu),
			    ZRAM_DSTMEM_ORDER);
		per_cpu(zram_dstmem, cpu) = NULL;
		break;
	default:
		break;
	}
	return NOTIFY_OK;
}

static struct notifier_block zram_cpu_notifier_block = {
	.notifier_call = zram_cpu_notifier
};

/* Helper function releasing tfms from online cpus */
static inline void zram_comp_cpus_down(void)
{
	int cpu;

	get_online_cpus();
	for_each_online_cpu(cpu) {
		void *pcpu = (void *)(long)cpu;
		zram_cpu_notifier(&zram_cpu_notifier_block,
				  CPU_UP_CANCELED, pcpu);
	}
	put_online_cpus();
}

static int zram_cpu_init(void)
{
	int ret;
	unsigned int cpu;

	ret = register_cpu_notifier(&zram_cpu_notifier_block);
	if (ret) {
		pr_err("zram: can't register cpu notifier\n");
		goto out;
	}

	get_online_cpus();
	for_each_online_cpu(cpu) {
		void *pcpu = (void *)(long)cpu;
		if (zram_cpu_notifier(&zram_cpu_notifier_block,
				      CPU_UP_PREPARE, pcpu) != NOTIFY_OK)
			goto cleanup;
	}
	put_online_cpus();
	return ret;

cleanup:
	zram_comp_cpus_down();

out:
	put_online_cpus();
	return -ENOMEM;
}
/* end of Cryptographic API features */

static void zram_stat64_add(struct zram *zram, u64 *v, u64 inc)
{
	struct zram *zram = dev_to_zram(dev);

	return sprintf(buf, "%llu\n",
			(u64)atomic64_read(&zram->stats.notify_free));
}

static ssize_t zero_pages_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct zram *zram = dev_to_zram(dev);

	return sprintf(buf, "%u\n", zram->stats.pages_zero);
}

static ssize_t orig_data_size_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct zram *zram = dev_to_zram(dev);

	return sprintf(buf, "%llu\n",
		(u64)(zram->stats.pages_stored) << PAGE_SHIFT);
}

static ssize_t compr_data_size_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct zram *zram = dev_to_zram(dev);

	return sprintf(buf, "%llu\n",
			(u64)atomic64_read(&zram->stats.compr_size));
}

static ssize_t mem_used_total_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	u64 val = 0;
	struct zram *zram = dev_to_zram(dev);
	struct zram_meta *meta = zram->meta;

	down_read(&zram->init_lock);
	if (zram->init_done)
		val = zs_get_total_size_bytes(meta->mem_pool);
	up_read(&zram->init_lock);

	return sprintf(buf, "%llu\n", val);
}

static int zram_test_flag(struct zram_meta *meta, u32 index,
			enum zram_pageflags flag)
{
	return meta->table[index].flags & BIT(flag);
}

static void zram_set_flag(struct zram_meta *meta, u32 index,
			enum zram_pageflags flag)
{
	meta->table[index].flags |= BIT(flag);
}

static void zram_clear_flag(struct zram_meta *meta, u32 index,
			enum zram_pageflags flag)
{
	meta->table[index].flags &= ~BIT(flag);
}

static inline int is_partial_io(struct bio_vec *bvec)
{
	return bvec->bv_len != PAGE_SIZE;
}

static inline int valid_io_request(struct zram *zram, struct bio *bio)
{
	u64 start, end, bound;

	
	if (unlikely(bio->bi_sector & (ZRAM_SECTOR_PER_LOGICAL_BLOCK - 1)))
		return 0;
	if (unlikely(bio->bi_size & (ZRAM_LOGICAL_BLOCK_SIZE - 1)))
		return 0;

	start = bio->bi_sector;
	end = start + (bio->bi_size >> SECTOR_SHIFT);
	bound = zram->disksize >> SECTOR_SHIFT;
	
	if (unlikely(start >= bound || end > bound || start > end))
		return 0;

	
	return 1;
}

static void zram_free_page(struct zram *zram, size_t index)
{
	unsigned long handle = zram->table[index].handle;
	u16 size = zram->table[index].size;

	meta->compress_workmem = kzalloc(LZO1X_MEM_COMPRESS, GFP_KERNEL);
	if (!meta->compress_workmem)
		goto free_meta;

	meta->compress_buffer =
		(void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, 1);
	if (!meta->compress_buffer) {
		pr_err("Error allocating compressor buffer space\n");
		goto free_workmem;
	}

	if (unlikely(size > max_zpage_size))
		zram_stat_dec(&zram->stats.bad_compress);

	meta->mem_pool = zs_create_pool(GFP_NOIO | __GFP_HIGHMEM |
					__GFP_NOWARN);
	if (!meta->mem_pool) {
		pr_err("Error creating memory pool\n");
		goto free_table;
	}

	if (size <= PAGE_SIZE / 2)
		zram_stat_dec(&zram->stats.good_compress);

	zram_stat64_sub(zram, &zram->stats.compr_size,
			zram->table[index].size);
	zram_stat_dec(&zram->stats.pages_stored);

	zram->table[index].handle = 0;
	zram->table[index].size = 0;
}

static int page_zero_filled(void *ptr)
{
	unsigned int pos;
	unsigned long *page;

	page = (unsigned long *)ptr;

	for (pos = 0; pos != PAGE_SIZE / sizeof(*page); pos++) {
		if (page[pos])
			return 0;
	}

	return 1;
}

static inline int is_partial_io(struct bio_vec *bvec)
{
	return bvec->bv_len != PAGE_SIZE;
}

static int zram_decompress_page(struct zram *zram, char *mem, u32 index)
{
	int ret = 0;
	size_t clen = PAGE_SIZE;
	unsigned char *cmem;
	unsigned long handle = zram->table[index].handle;

	if (!handle || zram_test_flag(zram, index, ZRAM_ZERO)) {
		memset(mem, 0, PAGE_SIZE);
		return 0;
	}

	cmem = zs_map_object(zram->mem_pool, handle, ZS_MM_RO);
	if (zram->table[index].size == PAGE_SIZE)
		memcpy(mem, cmem, PAGE_SIZE);
	else
		ret = zram_comp_op(ZRAM_COMPOP_DECOMPRESS, cmem,
				zram->table[index].size, mem, &clen);

	zs_unmap_object(zram->mem_pool, handle);

	/* Should NEVER happen. Return bio error if it does. */
	if (unlikely(ret != 0)) {
		pr_err("Decompression failed! err=%d, page=%u\n", ret, index);
		atomic64_inc(&zram->stats.failed_reads);
		return ret;
	}

	return 0;
}

static int zram_bvec_read(struct zram *zram, struct bio_vec *bvec,
			  u32 index, int offset, struct bio *bio)
{
	int ret;
	struct page *page;
	unsigned char *user_mem, *uncmem = NULL;

	page = bvec->bv_page;

	if (unlikely(!zram->table[index].handle) ||
			zram_test_flag(zram, index, ZRAM_ZERO)) {
		handle_zero_page(bvec);
		return 0;
	}

	if (is_partial_io(bvec))
		/* Use  a temporary buffer to decompress the page */
		uncmem = kmalloc(PAGE_SIZE, GFP_NOIO);

	user_mem = kmap_atomic(page);
	if (!is_partial_io(bvec))
		uncmem = user_mem;

	if (!uncmem) {
		pr_info("Unable to allocate temp memory\n");
		ret = -ENOMEM;
		goto out_cleanup;
	}

	ret = zram_decompress_page(zram, uncmem, index);
	/* Should NEVER happen. Return bio error if it does. */
	if (unlikely(ret != 0)) {
		pr_err("Decompression failed! err=%d, page=%u\n", ret, index);
		zram_stat64_inc(zram, &zram->stats.failed_reads);
		goto out_cleanup;
	}

	if (is_partial_io(bvec))
		memcpy(user_mem + bvec->bv_offset, uncmem + offset,
				bvec->bv_len);

	flush_dcache_page(page);
	ret = 0;
out_cleanup:
	kunmap_atomic(user_mem);
	if (is_partial_io(bvec))
		kfree(uncmem);
	return ret;
}

static int zram_bvec_write(struct zram *zram, struct bio_vec *bvec, u32 index,
			   int offset)
{
	int ret = 0;
	size_t clen;
	unsigned long handle;
	struct page *page;
	unsigned char *user_mem, *cmem, *src, *uncmem = NULL;
	struct zram_meta *meta = zram->meta;
	static unsigned long zram_rs_time;

	page = bvec->bv_page;
	src = meta->compress_buffer;

	if (is_partial_io(bvec)) {
		/*
		 * This is a partial IO. We need to read the full page
		 * before to write the changes.
		 */
		uncmem = kmalloc(PAGE_SIZE, GFP_NOIO);
		if (!uncmem) {
			ret = -ENOMEM;
			goto out;
		}
		ret = zram_decompress_page(zram, uncmem, index);
		if (ret)
			goto out;
	}

	user_mem = kmap_atomic(page);

	if (is_partial_io(bvec)) {
		memcpy(uncmem + offset, user_mem + bvec->bv_offset,
		       bvec->bv_len);
		kunmap_atomic(user_mem);
		user_mem = NULL;
	} else {
		uncmem = user_mem;
	}

	if (page_zero_filled(uncmem)) {
		if (!is_partial_io(bvec))
			kunmap_atomic(user_mem);
		zram_stat_inc(&zram->stats.pages_zero);
		zram_set_flag(zram, index, ZRAM_ZERO);
		ret = 0;
		goto out;
	}

	ret = zram_comp_op(ZRAM_COMPOP_COMPRESS, uncmem,
			   PAGE_SIZE, src, &clen);

	if (!is_partial_io(bvec)) {
		kunmap_atomic(user_mem);
		user_mem = NULL;
		uncmem = NULL;
	}

	if (unlikely(ret != 0)) {
		pr_err("Compression failed! err=%d\n", ret);
		goto out;
	}

	if (unlikely(clen > max_zpage_size)) {
		zram_stat_inc(&zram->stats.bad_compress);
		clen = PAGE_SIZE;
		src = NULL;
		if (is_partial_io(bvec))
			src = uncmem;
	}

	handle = zs_malloc(zram->mem_pool, clen);
	if (!handle) {
		if (printk_timed_ratelimit(&zram_rs_time,
					   ALLOC_ERROR_LOG_RATE_MS))
			pr_info("Error allocating memory for compressed page: %u, size=%zu\n",
				index, clen);
		ret = -ENOMEM;
		goto out;
	}
	cmem = zs_map_object(zram->mem_pool, handle, ZS_MM_WO);

	if ((clen == PAGE_SIZE) && !is_partial_io(bvec))
		src = kmap_atomic(page);
	memcpy(cmem, src, clen);
	if ((clen == PAGE_SIZE) && !is_partial_io(bvec))
		kunmap_atomic(src);

	zs_unmap_object(zram->mem_pool, handle);

	zs_unmap_object(meta->mem_pool, handle);

	zram_free_page(zram, index);

out:
	if (is_partial_io(bvec))
		kfree(uncmem);

	if (ret)
		atomic64_inc(&zram->stats.failed_writes);
	return ret;
}

static void handle_pending_slot_free(struct zram *zram)
{
	struct zram_slot_free *free_rq;

	spin_lock(&zram->slot_free_lock);
	while (zram->slot_free_rq) {
		free_rq = zram->slot_free_rq;
		zram->slot_free_rq = free_rq->next;
		zram_free_page(zram, free_rq->index);
		kfree(free_rq);
	}
	spin_unlock(&zram->slot_free_lock);
}

static int zram_bvec_rw(struct zram *zram, struct bio_vec *bvec, u32 index,
			int offset, struct bio *bio, int rw)
{
	int ret;

	if (rw == READ) {
		down_read(&zram->lock);
		handle_pending_slot_free(zram);
		ret = zram_bvec_read(zram, bvec, index, offset, bio);
		up_read(&zram->lock);
	} else {
		down_write(&zram->lock);
		handle_pending_slot_free(zram);
		ret = zram_bvec_write(zram, bvec, index, offset);
		up_write(&zram->lock);
	}

	return ret;
}

static void zram_reset_device(struct zram *zram, bool reset_capacity)
{
	size_t index;
	struct zram_meta *meta;

	flush_work(&zram->free_work);

	down_write(&zram->init_lock);
	if (!zram->init_done) {
		up_write(&zram->init_lock);
		return;
	}

	meta = zram->meta;
	zram->init_done = 0;

	
	for (index = 0; index < zram->disksize >> PAGE_SHIFT; index++) {
		unsigned long handle = meta->table[index].handle;
		if (!handle)
			continue;

		zs_free(meta->mem_pool, handle);
	}

	zram_meta_free(zram->meta);
	zram->meta = NULL;
	
	memset(&zram->stats, 0, sizeof(zram->stats));

	zram->disksize = 0;
	if (reset_capacity)
		set_capacity(zram->disk, 0);
	up_write(&zram->init_lock);
}

static void zram_init_device(struct zram *zram, struct zram_meta *meta)
{
	if (zram->disksize > 2 * (totalram_pages << PAGE_SHIFT)) {
		pr_info(
		"There is little point creating a zram of greater than "
		"twice the size of memory since we expect a 2:1 compression "
		"ratio. Note that zram uses about 0.1%% of the size of "
		"the disk when not in use so a huge zram is "
		"wasteful.\n"
		"\tMemory Size: %lu kB\n"
		"\tSize you selected: %llu kB\n"
		"Continuing anyway ...\n",
		(totalram_pages << PAGE_SHIFT) >> 10, zram->disksize >> 10
		);
	}

	
	queue_flag_set_unlocked(QUEUE_FLAG_NONROT, zram->disk->queue);

	zram->meta = meta;
	zram->init_done = 1;

	pr_debug("Initialization done!\n");
}

static ssize_t disksize_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	u64 disksize;
	struct zram_meta *meta;
	struct zram *zram = dev_to_zram(dev);

	disksize = memparse(buf, NULL);
	if (!disksize)
		return -EINVAL;

	disksize = PAGE_ALIGN(disksize);
	meta = zram_meta_alloc(disksize);
	down_write(&zram->init_lock);
	if (zram->init_done) {
		up_write(&zram->init_lock);
		if (meta)
		    zram_meta_free(meta);
		pr_info("Cannot change disksize for initialized device\n");
		return -EBUSY;
	}

	zram->disksize = disksize;
	set_capacity(zram->disk, zram->disksize >> SECTOR_SHIFT);
	zram_init_device(zram, meta);
	up_write(&zram->init_lock);

	return len;
}

static ssize_t reset_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t len)
{
	int ret;
	unsigned short do_reset;
	struct zram *zram;
	struct block_device *bdev;

	zram = dev_to_zram(dev);
	bdev = bdget_disk(zram->disk, 0);

	if (!bdev)
		return -ENOMEM;

	
	if (bdev->bd_holders) {
		ret = -EBUSY;
		goto out;
	}

	ret = kstrtou16(buf, 10, &do_reset);
	if (ret)
		goto out;

	if (!do_reset) {
		ret = -EINVAL;
		goto out;
	}

	
	fsync_bdev(bdev);
	bdput(bdev);

	zram_reset_device(zram, true);
	return len;

out:
	bdput(bdev);
	return ret;
}

static void __zram_make_request(struct zram *zram, struct bio *bio, int rw)
{
	int i, offset;
	u32 index;
	struct bio_vec *bvec;

	switch (rw) {
	case READ:
		atomic64_inc(&zram->stats.num_reads);
		break;
	case WRITE:
		atomic64_inc(&zram->stats.num_writes);
		break;
	}

	index = bio->bi_sector >> SECTORS_PER_PAGE_SHIFT;
	offset = (bio->bi_sector & (SECTORS_PER_PAGE - 1)) << SECTOR_SHIFT;

	bio_for_each_segment(bvec, bio, i) {
		int max_transfer_size = PAGE_SIZE - offset;

		if (bvec->bv_len > max_transfer_size) {
			struct bio_vec bv;

			bv.bv_page = bvec->bv_page;
			bv.bv_len = max_transfer_size;
			bv.bv_offset = bvec->bv_offset;

			if (zram_bvec_rw(zram, &bv, index, offset, bio, rw) < 0)
				goto out;

			bv.bv_len = bvec->bv_len - max_transfer_size;
			bv.bv_offset += max_transfer_size;
			if (zram_bvec_rw(zram, &bv, index+1, 0, bio, rw) < 0)
				goto out;
		} else
			if (zram_bvec_rw(zram, bvec, index, offset, bio, rw)
			    < 0)
				goto out;

		update_position(&index, &offset, bvec);
	}

	set_bit(BIO_UPTODATE, &bio->bi_flags);
	bio_endio(bio, 0);
	return;

out:
	bio_io_error(bio);
}

static void zram_make_request(struct request_queue *queue, struct bio *bio)
{
	struct zram *zram = queue->queuedata;

	down_read(&zram->init_lock);
	if (unlikely(!zram->init_done))
		goto error;

	if (!valid_io_request(zram, bio)) {
		zram_stat64_inc(zram, &zram->stats.invalid_io);
		goto error;
	}

	__zram_make_request(zram, bio, bio_data_dir(bio));
	up_read(&zram->init_lock);

	return;

error:
	up_read(&zram->init_lock);
	bio_io_error(bio);
}

static void zram_slot_free(struct work_struct *work)
{
	size_t index;

	if (!zram->init_done)
		return;

	zram->init_done = 0;

	/* Free various per-device buffers */
	kfree(zram->compress_workmem);
	free_pages((unsigned long)zram->compress_buffer, 1);

	zram->compress_workmem = NULL;
	zram->compress_buffer = NULL;

	/* Free all pages that are still in this zram device */
	for (index = 0; index < zram->disksize >> PAGE_SHIFT; index++) {
		unsigned long handle = zram->table[index].handle;
		if (!handle)
			continue;

		zs_free(zram->mem_pool, handle);
	}

	vfree(zram->table);
	zram->table = NULL;

	zs_destroy_pool(zram->mem_pool);
	zram->mem_pool = NULL;

	/* Reset stats */
	memset(&zram->stats, 0, sizeof(zram->stats));

	zram->disksize = 0;
	set_capacity(zram->disk, 0);
}

static void add_slot_free(struct zram *zram, struct zram_slot_free *free_rq)
{
	down_write(&zram->init_lock);
	__zram_reset_device(zram);
	up_write(&zram->init_lock);
}

/* zram->init_lock should be held */
int zram_init_device(struct zram *zram)
{
	int ret;
	size_t num_pages;

	if (zram->disksize > 2 * (totalram_pages << PAGE_SHIFT)) {
		pr_info(
		"There is little point creating a zram of greater than "
		"twice the size of memory since we expect a 2:1 compression "
		"ratio. Note that zram uses about 0.1%% of the size of "
		"the disk when not in use so a huge zram is "
		"wasteful.\n"
		"\tMemory Size: %lu kB\n"
		"\tSize you selected: %llu kB\n"
		"Continuing anyway ...\n",
		(totalram_pages << PAGE_SHIFT) >> 10, zram->disksize >> 10
		);
	}

	zram->compress_buffer =
		(void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, 1);
	if (!zram->compress_buffer) {
		pr_err("Error allocating compressor buffer space\n");
		ret = -ENOMEM;
		goto fail_no_table;
	}

	num_pages = zram->disksize >> PAGE_SHIFT;
	zram->table = vzalloc(num_pages * sizeof(*zram->table));
	if (!zram->table) {
		pr_err("Error allocating zram address table\n");
		ret = -ENOMEM;
		goto fail_no_table;
	}

	/* zram devices sort of resembles non-rotational disks */
	queue_flag_set_unlocked(QUEUE_FLAG_NONROT, zram->disk->queue);

	zram->mem_pool = zs_create_pool("zram", GFP_NOIO | __GFP_HIGHMEM);
	if (!zram->mem_pool) {
		pr_err("Error creating memory pool\n");
		ret = -ENOMEM;
		goto fail;
	}

	zram->init_done = 1;

	pr_debug("Initialization done!\n");
	return 0;

fail_no_table:
	/* To prevent accessing table entries during cleanup */
	zram->disksize = 0;
fail:
	__zram_reset_device(zram);
	pr_err("Initialization failed: err=%d\n", ret);
	return ret;
}

static void zram_slot_free_notify(struct block_device *bdev,
				unsigned long index)
{
	struct zram *zram;
	struct zram_slot_free *free_rq;

	zram = bdev->bd_disk->private_data;
	atomic64_inc(&zram->stats.notify_free);

	free_rq = kmalloc(sizeof(struct zram_slot_free), GFP_ATOMIC);
	if (!free_rq)
		return;

	free_rq->index = index;
	add_slot_free(zram, free_rq);
	schedule_work(&zram->free_work);
}

static const struct block_device_operations zram_devops = {
	.swap_slot_free_notify = zram_slot_free_notify,
	.owner = THIS_MODULE
};

static DEVICE_ATTR(disksize, S_IRUGO | S_IWUSR,
		disksize_show, disksize_store);
static DEVICE_ATTR(initstate, S_IRUGO, initstate_show, NULL);
static DEVICE_ATTR(reset, S_IWUSR, NULL, reset_store);
static DEVICE_ATTR(num_reads, S_IRUGO, num_reads_show, NULL);
static DEVICE_ATTR(num_writes, S_IRUGO, num_writes_show, NULL);
static DEVICE_ATTR(invalid_io, S_IRUGO, invalid_io_show, NULL);
static DEVICE_ATTR(notify_free, S_IRUGO, notify_free_show, NULL);
static DEVICE_ATTR(zero_pages, S_IRUGO, zero_pages_show, NULL);
static DEVICE_ATTR(orig_data_size, S_IRUGO, orig_data_size_show, NULL);
static DEVICE_ATTR(compr_data_size, S_IRUGO, compr_data_size_show, NULL);
static DEVICE_ATTR(mem_used_total, S_IRUGO, mem_used_total_show, NULL);

static struct attribute *zram_disk_attrs[] = {
	&dev_attr_disksize.attr,
	&dev_attr_initstate.attr,
	&dev_attr_reset.attr,
	&dev_attr_num_reads.attr,
	&dev_attr_num_writes.attr,
	&dev_attr_invalid_io.attr,
	&dev_attr_notify_free.attr,
	&dev_attr_zero_pages.attr,
	&dev_attr_orig_data_size.attr,
	&dev_attr_compr_data_size.attr,
	&dev_attr_mem_used_total.attr,
	NULL,
};

static struct attribute_group zram_disk_attr_group = {
	.attrs = zram_disk_attrs,
};

static int create_device(struct zram *zram, int device_id)
{
	int ret = -ENOMEM;

	init_rwsem(&zram->lock);
	init_rwsem(&zram->init_lock);

	INIT_WORK(&zram->free_work, zram_slot_free);
	spin_lock_init(&zram->slot_free_lock);
	zram->slot_free_rq = NULL;

	zram->queue = blk_alloc_queue(GFP_KERNEL);
	if (!zram->queue) {
		pr_err("Error allocating disk queue for device %d\n",
			device_id);
		goto out;
	}

	blk_queue_make_request(zram->queue, zram_make_request);
	zram->queue->queuedata = zram;

	 
	zram->disk = alloc_disk(1);
	if (!zram->disk) {
		blk_cleanup_queue(zram->queue);
		pr_warn("Error allocating disk structure for device %d\n",
			device_id);
		goto out_free_queue;
	}

	zram->disk->major = zram_major;
	zram->disk->first_minor = device_id;
	zram->disk->fops = &zram_devops;
	zram->disk->queue = zram->queue;
	zram->disk->private_data = zram;
	snprintf(zram->disk->disk_name, 16, "zram%d", device_id);

	
	set_capacity(zram->disk, 0);

	blk_queue_physical_block_size(zram->disk->queue, PAGE_SIZE);
	blk_queue_logical_block_size(zram->disk->queue,
					ZRAM_LOGICAL_BLOCK_SIZE);
	blk_queue_io_min(zram->disk->queue, PAGE_SIZE);
	blk_queue_io_opt(zram->disk->queue, PAGE_SIZE);

	add_disk(zram->disk);

	ret = sysfs_create_group(&disk_to_dev(zram->disk)->kobj,
				&zram_disk_attr_group);
	if (ret < 0) {
		pr_warn("Error creating sysfs group");
		goto out;
	}

	zram->init_done = 0;
	return 0;

out_free_disk:
	del_gendisk(zram->disk);
	put_disk(zram->disk);
out_free_queue:
	blk_cleanup_queue(zram->queue);
out:
	return ret;
}

static void destroy_device(struct zram *zram)
{
	sysfs_remove_group(&disk_to_dev(zram->disk)->kobj,
			&zram_disk_attr_group);

	del_gendisk(zram->disk);
	put_disk(zram->disk);

	blk_cleanup_queue(zram->queue);
}

static int __init zram_init(void)
{
	int ret, dev_id;

	/* Initialize Cryptographic API */
	pr_info("Loading Crypto API features\n");
	if (zram_comp_init()) {
		pr_err("Compressor initialization failed\n");
		ret = -ENOMEM;
		goto out;
	}

	if (zram_cpu_init()) {
		pr_err("Per-cpu initialization failed\n");
		ret = -ENOMEM;
		goto free_comp;
	}

	if (num_devices > max_num_devices) {
		pr_warn("Invalid value for num_devices: %u\n",
				num_devices);
		ret = -EINVAL;
		goto free_cpu_comp;
	}

	zram_major = register_blkdev(0, "zram");
	if (zram_major <= 0) {
		pr_warn("Unable to get major number\n");
		ret = -EBUSY;
		goto free_cpu_comp;
	}

	/* Allocate the device array and initialize each one */
	zram_devices = kzalloc(num_devices * sizeof(struct zram), GFP_KERNEL);
	if (!zram_devices) {
		ret = -ENOMEM;
		goto unregister;
	}

	for (dev_id = 0; dev_id < num_devices; dev_id++) {
		ret = create_device(&zram_devices[dev_id], dev_id);
		if (ret)
			goto free_devices;
	}

	pr_info("Created %u device(s) ...\n", num_devices);

	return 0;

free_devices:
	while (dev_id)
		destroy_device(&zram_devices[--dev_id]);
	kfree(zram_devices);
unregister:
	unregister_blkdev(zram_major, "zram");
free_cpu_comp:
	zram_comp_cpus_down();
free_comp:
	zram_comp_exit();
out:
	return ret;
}

static void __exit zram_exit(void)
{
	int i;
	struct zram *zram;

	for (i = 0; i < num_devices; i++) {
		zram = &zram_devices[i];

		destroy_device(zram);
		zram_reset_device(zram);
	}

	unregister_blkdev(zram_major, "zram");

	kfree(zram_devices);
	zram_comp_cpus_down();
	zram_comp_exit();
	pr_debug("Cleanup done!\n");
}

module_init(zram_init);
module_exit(zram_exit);

module_param_named(compressor, zram_compressor, charp, 0);
MODULE_PARM_DESC(compressor, "Compressor type");

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Nitin Gupta <ngupta@vflare.org>");
MODULE_DESCRIPTION("Compressed RAM Block Device");
