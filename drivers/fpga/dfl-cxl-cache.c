// SPDX-License-Identifier: GPL-2.0-only
/*
 * DFL device driver for Host Exerciser Cache private feature.
 *
 * Provides a means of accessing the device MMIO and the
 * capability to pin buffers and program their physical
 * addresses into the HE-Cache registers. User interface
 * is exposed via /dev/dfl-cxl-cache.X as described in
 * include/uapi/linux/fpga-dfl.h.
 *
 * Copyright (C) 2023 Intel Corporation, Inc.
 *
 * Authors:
 *   Tim Whisonant <tim.whisonant@intel.com>
 *   Ananda Ravuri <ananda.ravuri@intel.com>
 */

#include <linux/bitfield.h>
#include <linux/cdev.h>
#include <linux/dfl.h>
#include <linux/errno.h>
#include <linux/fpga-dfl.h>
#include <linux/highmem.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#define DFL_CXL_CACHE_DRIVER_NAME	"dfl-cxl-cache"
#define FME_FEATURE_ID_CXL_CACHE	0x25

struct dfl_cxl_cache_buffer_region {
	u64 user_addr;
	u64 length;
	struct page **pages;
	phys_addr_t phys;
	__u64 offset[DFL_ARRAY_MAX_SIZE];
	struct rb_node node;
};

struct dfl_cxl_cache {
	struct dfl_device *ddev;
	int id;
	struct device *dev;
	struct cdev cdev;
	atomic_t opened;
	void __iomem *mmio_base;
	int mmio_size;
	struct dfl_cxl_cache_region_info rinfo;
	struct rb_root dma_regions;
};

static DEFINE_MUTEX(dfl_cxl_cache_class_lock);
static struct class *dfl_cxl_cache_class;
static dev_t dfl_cxl_cache_devt;
static int dfl_cxl_cache_devices;

static int dfl_cxl_cache_open(struct inode *inode, struct file *filp)
{
	struct dfl_cxl_cache *cxl_cache = container_of(inode->i_cdev, struct dfl_cxl_cache, cdev);

	if (atomic_cmpxchg(&cxl_cache->opened, 0, 1))
		return -EBUSY;

	filp->private_data = cxl_cache;

	return 0;
}

static long cxl_cache_ioctl_check_extension(struct dfl_cxl_cache *cxl_cache, unsigned long arg)
{
	/* No extension support for now */
	return 0;
}

static long cxl_cache_ioctl_get_region_info(struct dfl_cxl_cache *cxl_cache, void __user *arg)
{
	struct dfl_cxl_cache_region_info rinfo;
	unsigned long minsz;

	minsz = offsetofend(struct dfl_cxl_cache_region_info, offset);

	if (copy_from_user(&rinfo, arg, minsz))
		return -EFAULT;

	if (rinfo.argsz < minsz)
		return -EINVAL;

	rinfo.flags = cxl_cache->rinfo.flags;
	rinfo.size = cxl_cache->rinfo.size;
	rinfo.offset = cxl_cache->rinfo.offset;

	if (copy_to_user(arg, &rinfo, sizeof(rinfo)))
		return -EFAULT;

	return 0;
}

static void cxl_cache_unpin_pages(struct device *dev, struct page ***pages, unsigned long length)
{
	const long npages = PFN_DOWN(length);

	if (!*pages)
		return;

	unpin_user_pages(*pages, npages);
	kfree(*pages);
	*pages = NULL;
	account_locked_vm(current->mm, npages, false);

	dev_dbg(dev, "%ld pages unpinned\n", npages);
}

/**
 * cxl_cache_dsm_check_continuous_pages - check if pages are continuous
 * @region: dma memory region
 *
 * Return true if pages of given dma memory region have continuous physical
 * address, otherwise return false.
 */
static bool cxl_cache_check_continuous_pages(struct page **pages, unsigned long length)
{
	int i;
	const int npages = PFN_DOWN(length);

	for (i = 0; i < npages - 1; i++)
		if (page_to_pfn(pages[i]) + 1 != page_to_pfn(pages[i + 1]))
			return false;

	return true;
}

static int cxl_cache_dma_pin_pages(struct dfl_cxl_cache *cxl_cache,
				   struct dfl_cxl_cache_buffer_region *region)
{
	int ret, pinned;
	const unsigned int flags = FOLL_LONGTERM | FOLL_WRITE;
	const int npages = PFN_DOWN(region->length);

	ret = account_locked_vm(current->mm, npages, true);
	if (ret)
		return ret;

	region->pages = kzalloc(npages * sizeof(struct page *), GFP_KERNEL);
	if (!region->pages) {
		ret = -ENOMEM;
		goto unlock_vm;
	}

	pinned = pin_user_pages_fast(region->user_addr, npages, flags, region->pages);
	if (pinned < 0) {
		ret = pinned;
		goto free_pages;
	} else if (pinned != npages) {
		ret = -EFAULT;
		goto unpin_pages;
	}
	dev_dbg(cxl_cache->dev, "%d pages pinned\n", pinned);

	return 0;

unpin_pages:
	unpin_user_pages(region->pages, pinned);
free_pages:
	kfree(region->pages);
unlock_vm:
	account_locked_vm(current->mm, npages, false);
	return ret;
}

static void cxl_cache_dma_region_remove(struct dfl_cxl_cache *cxl_cache,
					struct dfl_cxl_cache_buffer_region *region)
{
	dev_dbg(cxl_cache->dev, "del region (user_addr = %llx)\n", region->user_addr);
	rb_erase(&region->node, &cxl_cache->dma_regions);
}

static bool dma_region_check_user_addr(struct dfl_cxl_cache_buffer_region *region, u64 user_addr,
				       u64 size)
{
	if (!size && region->user_addr != user_addr)
		return false;

	return (region->user_addr <= user_addr) &&
		(region->length + region->user_addr >= user_addr + size);
}

struct dfl_cxl_cache_buffer_region*
	cxl_cache_dma_region_find(struct dfl_cxl_cache *cxl_cache, u64 user_addr, u64 size)
{
	struct rb_node *node = cxl_cache->dma_regions.rb_node;

	while (node) {
		struct dfl_cxl_cache_buffer_region *region;

		region = container_of(node, struct dfl_cxl_cache_buffer_region, node);

		if (dma_region_check_user_addr(region, user_addr, size)) {
			dev_dbg(cxl_cache->dev, "find region (user_addr = %llx)\n",
				region->user_addr);
			return region;
		}

		if (user_addr < region->user_addr)
			node = node->rb_left;
		else if (user_addr > region->user_addr)
			node = node->rb_right;
		else
			break;
	}

	dev_dbg(cxl_cache->dev, "region with user_addr %llx and size %llx is not found\n",
		user_addr, size);
	return NULL;
}

static int cxl_cache_dma_region_add(struct dfl_cxl_cache *cxl_cache,
				    struct dfl_cxl_cache_buffer_region *region)
{
	struct rb_node **new, *parent = NULL;

	dev_dbg(cxl_cache->dev, "add region (user_addr = %llx)\n", region->user_addr);
	new = &cxl_cache->dma_regions.rb_node;

	while (*new) {
		struct dfl_cxl_cache_buffer_region *this;

		this = container_of(*new, struct dfl_cxl_cache_buffer_region, node);
		parent = *new;

		if (dma_region_check_user_addr(this, region->user_addr, region->length))
			return -EEXIST;

		if (region->user_addr < this->user_addr)
			new = &((*new)->rb_left);
		else if (region->user_addr > this->user_addr)
			new = &((*new)->rb_right);
		else
			return -EEXIST;
	}

	rb_link_node(&region->node, parent, new);
	rb_insert_color(&region->node, &cxl_cache->dma_regions);

	return 0;
}

static long cxl_cache_ioctl_numa_buffer_map(struct dfl_cxl_cache *cxl_cache, void __user *arg)
{
	int i = 0;
	unsigned long minsz = 0;
	long ret = 0;
	struct dfl_cxl_cache_buffer_map dma_map;
	struct dfl_cxl_cache_buffer_region *region;

	minsz = offsetofend(struct dfl_cxl_cache_buffer_map, csr_array);
	if (copy_from_user(&dma_map, arg, minsz)) {
		dev_err(cxl_cache->dev, "fails to copy from user space buffer\n");
		return -EFAULT;
	}
	if (dma_map.argsz < minsz) {
		dev_err(cxl_cache->dev, "invalid ioctl buffer size\n");
		return -EINVAL;
	}

	/* Check Inputs, only accept page-aligned user memory region with valid length */
	if (!PAGE_ALIGNED(dma_map.user_addr) || !PAGE_ALIGNED(dma_map.length) ||
	    !(dma_map.length)) {
		dev_err(cxl_cache->dev, "length is not page-aligned or the length is zero\n");
		return -EINVAL;
	}

	/* Check overflow */
	if (dma_map.user_addr + dma_map.length < dma_map.user_addr) {
		dev_err(cxl_cache->dev, "dma buffer check overflow\n");
		return -EINVAL;
	}

	region = kzalloc(sizeof(*region), GFP_KERNEL);
	if (!region)
		return -ENOMEM;

	region->user_addr = dma_map.user_addr;
	region->length = dma_map.length;

	dev_dbg(cxl_cache->dev, "user_addr: %llx length: %lld\n",
		region->user_addr, region->length);

	/* Pin the user memory region */
	ret = cxl_cache_dma_pin_pages(cxl_cache, region);
	if (ret) {
		dev_err(cxl_cache->dev, "failed to pin pages\n");
		goto free_region;
	}

	/* Only accept continuous pages, return error else */
	if (!cxl_cache_check_continuous_pages(region->pages, region->length)) {
		dev_err(cxl_cache->dev, "pages are not continuous\n");
		ret = -EINVAL;
		goto out_unpin_pages;
	}

	ret = cxl_cache_dma_region_add(cxl_cache, region);

	if (ret) {
		dev_err(cxl_cache->dev, "failed to add dma region\n");
		goto out_unpin_pages;
	}

	region->phys = page_to_phys(region->pages[0]);

	for (i = 0; i < DFL_ARRAY_MAX_SIZE; i++) {
		if (dma_map.csr_array[i] != 0  && dma_map.csr_array[i] < cxl_cache->rinfo.size)
			writeq(region->phys, cxl_cache->mmio_base + dma_map.csr_array[i]);
	}

	dev_dbg(cxl_cache->dev, "phys address:%lld\n", region->phys);
	return 0;

out_unpin_pages:
	cxl_cache_unpin_pages(cxl_cache->dev, &region->pages, region->length);
free_region:
	kfree(region);
	return ret;
}

static long cxl_cache_ioctl_numa_buffer_unmap(struct dfl_cxl_cache *cxl_cache, void __user *arg)
{
	unsigned long minsz = 0;
	long ret = 0;
	int i = 0;
	struct dfl_cxl_cache_buffer_unmap dma_unmap;
	struct dfl_cxl_cache_buffer_region *region;

	minsz = offsetofend(struct dfl_cxl_cache_buffer_unmap, csr_array);
	if (copy_from_user(&dma_unmap, arg, minsz)) {
		dev_err(cxl_cache->dev, "fails to copy from user space buffer\n");
		return -EFAULT;
	}
	if (dma_unmap.argsz < minsz) {
		dev_err(cxl_cache->dev, "invalid ioctl buffer size\n");
		return -EINVAL;
	}

	dev_dbg(cxl_cache->dev, "user_addr: %llx length: %lld",
		dma_unmap.user_addr, dma_unmap.length);

	region = cxl_cache_dma_region_find(cxl_cache, dma_unmap.user_addr, dma_unmap.length);
	if (!region) {
		dev_err(cxl_cache->dev, "fails to find buffer\n");
		return -EINVAL;
	}

	cxl_cache_dma_region_remove(cxl_cache, region);
	cxl_cache_unpin_pages(cxl_cache->dev, &region->pages, region->length);

	for (i = 0; i < DFL_ARRAY_MAX_SIZE; i++) {
		if (dma_unmap.csr_array[i] != 0 && dma_unmap.csr_array[i] < cxl_cache->rinfo.size)
			writeq(0, cxl_cache->mmio_base + dma_unmap.csr_array[i]);
	}

	kfree(region);
	return ret;
}

static long dfl_cxl_cache_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct dfl_cxl_cache *cxl_cache = filp->private_data;

	switch (cmd) {
	case DFL_FPGA_GET_API_VERSION:
		return DFL_FPGA_GET_API_VERSION;
	case DFL_FPGA_CHECK_EXTENSION:
		return cxl_cache_ioctl_check_extension(cxl_cache, arg);
	case DFL_CXL_CACHE_GET_REGION_INFO:
		return cxl_cache_ioctl_get_region_info(cxl_cache, (void __user *)arg);
	case DFL_CXL_CACHE_NUMA_BUFFER_MAP:
		return cxl_cache_ioctl_numa_buffer_map(cxl_cache, (void __user *)arg);
	case DFL_CXL_CACHE_NUMA_BUFFER_UNMAP:
		return cxl_cache_ioctl_numa_buffer_unmap(cxl_cache, (void __user *)arg);
	}

	return -EINVAL;
}

static const struct vm_operations_struct cxl_cache_vma_ops = {
#ifdef CONFIG_HAVE_IOREMAP_PROT
	.access = generic_access_phys,
#endif
};

static int dfl_cxl_cache_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct dfl_cxl_cache *cxl_cache = filp->private_data;
	u64 size = vma->vm_end - vma->vm_start;
	u64 offset;

	if (!(vma->vm_flags & VM_SHARED))
		return -EINVAL;

	if (!(cxl_cache->rinfo.flags & DFL_CXL_CACHE_REGION_MMAP))
		return -EINVAL;

	if ((vma->vm_flags & VM_READ) && !(cxl_cache->rinfo.flags & DFL_CXL_CACHE_REGION_READ))
		return -EPERM;

	if ((vma->vm_flags & VM_WRITE) && !(cxl_cache->rinfo.flags & DFL_CXL_CACHE_REGION_WRITE))
		return -EPERM;

	offset = PFN_PHYS(vma->vm_pgoff);

	/* Support debug access to the mapping */
	vma->vm_ops = &cxl_cache_vma_ops;

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	return remap_pfn_range(vma, vma->vm_start,
			       PFN_DOWN(cxl_cache->ddev->mmio_res.start +
			       (offset - cxl_cache->rinfo.offset)),
			       size, vma->vm_page_prot);
}

void cxl_cache_dma_region_destroy(struct dfl_cxl_cache *cxl_cache)
{
	struct rb_node *node = rb_first(&cxl_cache->dma_regions);
	struct dfl_cxl_cache_buffer_region *region;

	while (node) {
		region = container_of(node, struct dfl_cxl_cache_buffer_region, node);

		dev_dbg(cxl_cache->dev, "del region (user_addr = %llx)\n", region->user_addr);
		rb_erase(node, &cxl_cache->dma_regions);

		if (region->pages)
			cxl_cache_unpin_pages(cxl_cache->dev, &region->pages, region->length);

		node = rb_next(node);
		kfree(region);
	}
}

static int dfl_cxl_cache_release(struct inode *inode, struct file *filp)
{
	struct dfl_cxl_cache *cxl_cache = filp->private_data;

	cxl_cache_dma_region_destroy(cxl_cache);
	atomic_set(&cxl_cache->opened, 0);
	return 0;
}

static const struct file_operations dfl_cxl_cache_fops = {
	.owner = THIS_MODULE,
	.open = dfl_cxl_cache_open,
	.release = dfl_cxl_cache_release,
	.unlocked_ioctl = dfl_cxl_cache_ioctl,
	.mmap = dfl_cxl_cache_mmap,
};

static void cxl_cache_dev_release(struct device *dev)
{
	struct dfl_cxl_cache *cxl_cache = dev_get_drvdata(dev);

	cdev_del(&cxl_cache->cdev);
}

static void cxl_cache_chardev_uinit(struct dfl_cxl_cache *cxl_cache)
{
	dev_set_drvdata(&cxl_cache->ddev->dev, NULL);
	device_destroy(dfl_cxl_cache_class,
		       MKDEV(MAJOR(dfl_cxl_cache_devt), cxl_cache->id));
}

static int cxl_cache_chardev_init(struct dfl_cxl_cache *cxl_cache,
				  struct dfl_device *ddev,
				  void __iomem *mmio_base)
{
	int ret;

	dev_set_drvdata(&ddev->dev, cxl_cache);
	cxl_cache->ddev = ddev;
	cxl_cache->mmio_base = mmio_base;
	cxl_cache->id = dfl_cxl_cache_devices++;
	cxl_cache->dma_regions = RB_ROOT;

	cxl_cache->rinfo.argsz = sizeof(struct dfl_cxl_cache_region_info);
	cxl_cache->rinfo.flags = DFL_CXL_CACHE_REGION_READ | DFL_CXL_CACHE_REGION_WRITE |
			   DFL_CXL_CACHE_REGION_MMAP;
	cxl_cache->rinfo.size = resource_size(&ddev->mmio_res);
	cxl_cache->rinfo.offset = 0;

	cxl_cache->dev = device_create(dfl_cxl_cache_class, &ddev->dev,
				       MKDEV(MAJOR(dfl_cxl_cache_devt), cxl_cache->id),
				       cxl_cache, DFL_CXL_CACHE_DRIVER_NAME ".%d",
				       cxl_cache->id);

	if (IS_ERR(cxl_cache->dev)) {
		ret = PTR_ERR(cxl_cache->dev);
		dev_err(&ddev->dev, "device_create failed: %d\n", ret);
		cxl_cache->dev = NULL;
		return ret;
	}
	cxl_cache->dev->release = cxl_cache_dev_release;

	dev_dbg(cxl_cache->dev, "added cxl_cache device: %s\n", dev_name(cxl_cache->dev));

	cdev_init(&cxl_cache->cdev, &dfl_cxl_cache_fops);
	cxl_cache->cdev.owner = THIS_MODULE;
	cxl_cache->cdev.ops = &dfl_cxl_cache_fops;

	ret = cdev_add(&cxl_cache->cdev, cxl_cache->dev->devt, 1);
	if (ret)
		dev_err(cxl_cache->dev, "cdev_add failed: %d\n", ret);

	return ret;
}

static int dfl_cxl_cache_probe(struct dfl_device *ddev)
{
	int ret = 0;
	void __iomem *mmio_base;
	struct dfl_cxl_cache *cxl_cache;

	mutex_lock(&dfl_cxl_cache_class_lock);

	if (!dfl_cxl_cache_class) {
		dfl_cxl_cache_class = class_create(THIS_MODULE, DFL_CXL_CACHE_DRIVER_NAME);
		if (IS_ERR(dfl_cxl_cache_class)) {
			ret = PTR_ERR(dfl_cxl_cache_class);
			dfl_cxl_cache_class = NULL;
			dev_err_probe(&ddev->dev, "class_create failed: %d\n", ret);
			goto out_unlock;
		}
	}

	if (!MAJOR(dfl_cxl_cache_devt)) {
		ret = alloc_chrdev_region(&dfl_cxl_cache_devt, 0,
					  MINORMASK,
					  DFL_CXL_CACHE_DRIVER_NAME);
		if (ret) {
			dev_err_probe(&ddev->dev, "alloc_chrdev_region failed: %d\n", ret);
			dfl_cxl_cache_devt = MKDEV(0, 0);
			goto out_unlock;
		}
	}

	mmio_base = devm_ioremap_resource(&ddev->dev, &ddev->mmio_res);
	if (IS_ERR(mmio_base)) {
		ret = PTR_ERR(mmio_base);
		dev_err_probe(&ddev->dev, "devm_ioremap_resource failed: %d\n", ret);
		goto out_unlock;
	}

	cxl_cache = devm_kzalloc(&ddev->dev, sizeof(*cxl_cache), GFP_KERNEL);
	if (!cxl_cache) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	ret = cxl_cache_chardev_init(cxl_cache, ddev, mmio_base);
	if (ret)
		dev_err_probe(&ddev->dev, "cxl_cache_chardev_init failed: %d\n", ret);

out_unlock:
	mutex_unlock(&dfl_cxl_cache_class_lock);

	return ret;
}

static void dfl_cxl_cache_remove(struct dfl_device *ddev)
{
	struct dfl_cxl_cache *cxl_cache = dev_get_drvdata(&ddev->dev);

	mutex_lock(&dfl_cxl_cache_class_lock);
	cxl_cache_chardev_uinit(cxl_cache);

	if (--dfl_cxl_cache_devices <= 0) {
		if (dfl_cxl_cache_class) {
			class_destroy(dfl_cxl_cache_class);
			dfl_cxl_cache_class = NULL;
		}

		if (MAJOR(dfl_cxl_cache_devt)) {
			unregister_chrdev_region(dfl_cxl_cache_devt, MINORMASK);
			dfl_cxl_cache_devt = MKDEV(0, 0);
		}
	}

	mutex_unlock(&dfl_cxl_cache_class_lock);
}

static const struct dfl_device_id dfl_cxl_cache_ids[] = {
	{ FME_ID, FME_FEATURE_ID_CXL_CACHE },
	{ }
};
MODULE_DEVICE_TABLE(dfl, dfl_cxl_cache_ids);

static struct dfl_driver dfl_cxl_cache_driver = {
	.drv	= {
		.name	= DFL_CXL_CACHE_DRIVER_NAME,
	},
	.id_table = dfl_cxl_cache_ids,
	.probe   = dfl_cxl_cache_probe,
	.remove = dfl_cxl_cache_remove,
};
module_dfl_driver(dfl_cxl_cache_driver);

MODULE_DESCRIPTION("DFL CXL Cache driver");
MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL");
