// SPDX-License-Identifier: GPL-2.0
/*
 * VFIO Mediated device driver for DFL devices
 *
 * Copyright (C) 2019-2020 Intel Corporation, Inc.
 */
#include <linux/device.h>
#include <linux/fpga/dfl-bus.h>
#include <linux/init.h>
#include <linux/iommu.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/kernel.h>
#include <linux/mdev.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/vfio.h>
#include <linux/uaccess.h>

struct vfio_mdev_dfl_dev {
	struct device *dev;
	void __iomem *ioaddr;
	resource_size_t phys;
	resource_size_t memsize;
	int num_irqs;
	u32 region_flags;
	atomic_t avail;
};

static ssize_t
name_show(struct kobject *kobj, struct device *dev, char *buf)
{
	return sprintf(buf, "%s-type1\n", dev_name(dev));
}
static MDEV_TYPE_ATTR_RO(name);

static ssize_t
available_instances_show(struct kobject *kobj, struct device *dev, char *buf)
{
	struct vfio_mdev_dfl_dev *vmdd = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", atomic_read(&vmdd->avail));
}
static MDEV_TYPE_ATTR_RO(available_instances);

static ssize_t device_api_show(struct kobject *kobj, struct device *dev,
			       char *buf)
{
	return sprintf(buf, "%s\n", VFIO_DEVICE_API_PLATFORM_STRING);
}
static MDEV_TYPE_ATTR_RO(device_api);

static struct attribute *mdev_types_attrs[] = {
	&mdev_type_attr_name.attr,
	&mdev_type_attr_device_api.attr,
	&mdev_type_attr_available_instances.attr,
	NULL,
};

static struct attribute_group dfl_mdev_type_group1 = {
	.name  = "1",
	.attrs = mdev_types_attrs,
};

static struct attribute_group *dfl_mdev_type_groups[] = {
	&dfl_mdev_type_group1,
	NULL,
};

static int dfl_mdev_create(struct kobject *kobj, struct mdev_device *mdev)
{
	struct vfio_mdev_dfl_dev *vmdd =
		dev_get_drvdata(mdev_parent_dev(mdev));

	if (atomic_dec_if_positive(&vmdd->avail) < 0)
		return -EPERM;

	return 0;
}

static int dfl_mdev_remove(struct mdev_device *mdev)
{
	struct vfio_mdev_dfl_dev *vmdd =
		dev_get_drvdata(mdev_parent_dev(mdev));

	atomic_inc(&vmdd->avail);

	return 0;
}

static ssize_t dfl_mdev_read(struct mdev_device *mdev, char __user *buf,
			     size_t count, loff_t *ppos)
{
	struct vfio_mdev_dfl_dev *vmdd =
		dev_get_drvdata(mdev_parent_dev(mdev));
	unsigned int done = 0;
	loff_t off = *ppos;

	if (off + count > vmdd->memsize)
		return -EFAULT;

	while (count) {
		size_t filled;

		if (count >= 8 && !(off % 8)) {
			u64 val;

			val = ioread64(vmdd->ioaddr + off);
			if (copy_to_user(buf, &val, 8))
				goto err;

			filled = 8;
		} else if (count >= 4 && !(off % 4)) {
			u32 val;

			val = ioread32(vmdd->ioaddr + off);
			if (copy_to_user(buf, &val, 4))
				goto err;

			filled = 4;
		} else if (count >= 2 && !(off % 2)) {
			u16 val;

			val = ioread16(vmdd->ioaddr + off);
			if (copy_to_user(buf, &val, 2))
				goto err;

			filled = 2;
		} else {
			u8 val;

			val = ioread8(vmdd->ioaddr + off);
			if (copy_to_user(buf, &val, 1))
				goto err;

			filled = 1;
		}

		count -= filled;
		done += filled;
		off += filled;
		buf += filled;
	}

	return done;
err:
	return -EFAULT;
}

static ssize_t dfl_mdev_write(struct mdev_device *mdev, const char __user *buf,
			      size_t count, loff_t *ppos)
{
	struct vfio_mdev_dfl_dev *vmdd =
		dev_get_drvdata(mdev_parent_dev(mdev));
	unsigned int done = 0;
	loff_t off = *ppos;

	if (off + count > vmdd->memsize)
		return -EFAULT;

	while (count) {
		size_t filled;

		if (count >= 8 && !(off % 8)) {
			u64 val;

			if (copy_from_user(&val, buf, 8))
				goto err;
			iowrite64(val, vmdd->ioaddr + off);

			filled = 8;
		} else if (count >= 4 && !(off % 4)) {
			u32 val;

			if (copy_from_user(&val, buf, 4))
				goto err;
			iowrite32(val, vmdd->ioaddr + off);

			filled = 4;
		} else if (count >= 2 && !(off % 2)) {
			u16 val;

			if (copy_from_user(&val, buf, 2))
				goto err;
			iowrite16(val, vmdd->ioaddr + off);

			filled = 2;
		} else {
			u8 val;

			if (copy_from_user(&val, buf, 1))
				goto err;
			iowrite8(val, vmdd->ioaddr + off);

			filled = 1;
		}

		count -= filled;
		done += filled;
		off += filled;
		buf += filled;
	}

	return done;
err:
	return -EFAULT;
}

static long dfl_mdev_ioctl(struct mdev_device *mdev, unsigned int cmd,
			   unsigned long arg)
{
	struct vfio_mdev_dfl_dev *vmdd =
		dev_get_drvdata(mdev_parent_dev(mdev));
	unsigned long minsz;

	switch (cmd) {
	case VFIO_DEVICE_GET_INFO:
	{
		struct vfio_device_info info;

		minsz = offsetofend(struct vfio_device_info, num_irqs);

		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if (info.argsz < minsz)
			return -EINVAL;

		info.flags = VFIO_DEVICE_FLAGS_PLATFORM;
		info.num_regions = 1;
		info.num_irqs = vmdd->num_irqs;

		return copy_to_user((void __user *)arg, &info, minsz) ?
			-EFAULT : 0;
	}
	case VFIO_DEVICE_GET_REGION_INFO:
	{
		struct vfio_region_info info;

		minsz = offsetofend(struct vfio_region_info, offset);

		if (copy_from_user(&info, (void __user *)arg, minsz))
			return -EFAULT;

		if (info.argsz < minsz)
			return -EINVAL;

		if (info.index >= 1)
			return -EINVAL;

		info.offset = 0;
		info.size = vmdd->memsize;
		info.flags = vmdd->region_flags;

		return copy_to_user((void __user *)arg, &info, minsz) ?
			-EFAULT : 0;
	}
	}

	return -ENOTTY;
}

static int dfl_mdev_mmap_mmio(struct vfio_mdev_dfl_dev *vmdd,
			      struct vm_area_struct *vma)
{
	u64 req_len, req_start;

	req_len = vma->vm_end - vma->vm_start;
	req_start = vma->vm_pgoff << PAGE_SHIFT;

	if (vmdd->memsize < PAGE_SIZE || req_start + req_len > vmdd->memsize)
		return -EINVAL;

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	return remap_pfn_range(vma, vma->vm_start,
			       (vmdd->phys + req_start) >> PAGE_SHIFT,
			       req_len, vma->vm_page_prot);
}

static int dfl_mdev_mmap(struct mdev_device *mdev, struct vm_area_struct *vma)
{
	struct vfio_mdev_dfl_dev *vmdd =
		dev_get_drvdata(mdev_parent_dev(mdev));

	if (vma->vm_end < vma->vm_start)
		return -EINVAL;
	if (!(vma->vm_flags & VM_SHARED))
		return -EINVAL;
	if (vma->vm_start & ~PAGE_MASK)
		return -EINVAL;
	if (vma->vm_end & ~PAGE_MASK)
		return -EINVAL;

	if (!(vmdd->region_flags & VFIO_REGION_INFO_FLAG_MMAP))
		return -EINVAL;

	if (!(vmdd->region_flags & VFIO_REGION_INFO_FLAG_READ) &&
	    (vma->vm_flags & VM_READ))
		return -EINVAL;

	if (!(vmdd->region_flags & VFIO_REGION_INFO_FLAG_WRITE) &&
	    (vma->vm_flags & VM_WRITE))
		return -EINVAL;

	vma->vm_private_data = vmdd;

	return dfl_mdev_mmap_mmio(vmdd, vma);
}

static int dfl_mdev_open(struct mdev_device *mdev)
{
	if (!try_module_get(THIS_MODULE))
		return -ENODEV;

	return 0;
}

static void dfl_mdev_close(struct mdev_device *mdev)
{
	module_put(THIS_MODULE);
}

static const struct mdev_parent_ops dfl_mdev_ops = {
	.owner                  = THIS_MODULE,
	.supported_type_groups  = dfl_mdev_type_groups,
	.create                 = dfl_mdev_create,
	.remove			= dfl_mdev_remove,
	.open                   = dfl_mdev_open,
	.release                = dfl_mdev_close,
	.read                   = dfl_mdev_read,
	.write                  = dfl_mdev_write,
	.ioctl		        = dfl_mdev_ioctl,
	.mmap			= dfl_mdev_mmap,
};

static int vfio_mdev_dfl_probe(struct dfl_device *dfl_dev)
{
	struct device *dev = &dfl_dev->dev;
	struct vfio_mdev_dfl_dev *vmdd;

	vmdd = devm_kzalloc(dev, sizeof(*vmdd), GFP_KERNEL);
	if (!vmdd)
		return -ENOMEM;

	dev_set_drvdata(&dfl_dev->dev, vmdd);

	atomic_set(&vmdd->avail, 1);
	vmdd->dev = &dfl_dev->dev;
	vmdd->phys = dfl_dev->mmio_res.start;
	vmdd->memsize = resource_size(&dfl_dev->mmio_res);
	vmdd->region_flags = VFIO_REGION_INFO_FLAG_READ |
			    VFIO_REGION_INFO_FLAG_WRITE;
	/*
	 * Only regions addressed with PAGE granularity may be MMAPed
	 * securely.
	 */
	if (!(vmdd->phys & ~PAGE_MASK) && !(vmdd->memsize & ~PAGE_MASK))
		vmdd->region_flags |= VFIO_REGION_INFO_FLAG_MMAP;

	vmdd->ioaddr = devm_ioremap_resource(&dfl_dev->dev, &dfl_dev->mmio_res);
	if (IS_ERR(vmdd->ioaddr)) {
		dev_err(dev, "get mem resource fail!\n");
		return PTR_ERR(vmdd->ioaddr);
	}

	/* irq not supported yet */
	vmdd->num_irqs = 0;

	return mdev_register_device(&dfl_dev->dev, &dfl_mdev_ops);
}

static void vfio_mdev_dfl_remove(struct dfl_device *dfl_dev)
{
	mdev_unregister_device(&dfl_dev->dev);
}

static struct dfl_driver vfio_mdev_dfl_driver = {
	.drv	= {
		.name       = "vfio-mdev-dfl",
	},
	.probe   = vfio_mdev_dfl_probe,
	.remove  = vfio_mdev_dfl_remove,
};

module_dfl_driver(vfio_mdev_dfl_driver);

MODULE_DESCRIPTION("VFIO MDEV DFL driver");
MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL v2");
