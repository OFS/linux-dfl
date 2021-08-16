// SPDX-License-Identifier: GPL-2.0
/*
 * FPGA Image Load Framework
 *
 * Copyright (C) 2019-2021 Intel Corporation, Inc.
 */

#include <linux/delay.h>
#include <linux/fpga/fpga-image-load.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#define IMAGE_LOAD_XA_LIMIT	XA_LIMIT(0, INT_MAX)
static DEFINE_XARRAY_ALLOC(fpga_image_load_xa);

static struct class *fpga_image_load_class;
static dev_t fpga_image_devt;

#define to_image_load(d) container_of(d, struct fpga_image_load, dev)

static void fpga_image_prog_complete(struct fpga_image_load *imgld)
{
	mutex_lock(&imgld->lock);
	imgld->progress = FPGA_IMAGE_PROG_IDLE;
	eventfd_signal(imgld->finished, 1);
	mutex_unlock(&imgld->lock);
}

static void fpga_image_do_load(struct work_struct *work)
{
	struct fpga_image_load *imgld;
	s32 ret, offset = 0;

	imgld = container_of(work, struct fpga_image_load, work);

	if (imgld->driver_unload) {
		imgld->err_code = FPGA_IMAGE_ERR_CANCELED;
		goto idle_exit;
	}

	get_device(&imgld->dev);
	if (!try_module_get(imgld->dev.parent->driver->owner)) {
		imgld->err_code = FPGA_IMAGE_ERR_BUSY;
		goto putdev_exit;
	}

	imgld->progress = FPGA_IMAGE_PROG_PREPARING;
	ret = imgld->ops->prepare(imgld, imgld->data, imgld->remaining_size);
	if (ret) {
		imgld->err_code = ret;
		goto modput_exit;
	}

	imgld->progress = FPGA_IMAGE_PROG_WRITING;
	while (imgld->remaining_size) {
		ret = imgld->ops->write(imgld, imgld->data, offset,
					imgld->remaining_size);
		if (ret <= 0) {
			if (!ret) {
				dev_warn(&imgld->dev,
					 "write-op wrote zero data\n");
				ret = -FPGA_IMAGE_ERR_RW_ERROR;
			}
			imgld->err_code = -ret;
			goto done;
		}

		imgld->remaining_size -= ret;
		offset += ret;
	}

	imgld->progress = FPGA_IMAGE_PROG_PROGRAMMING;
	ret = imgld->ops->poll_complete(imgld);
	if (ret)
		imgld->err_code = ret;

done:
	if (imgld->ops->cleanup)
		imgld->ops->cleanup(imgld);

modput_exit:
	module_put(imgld->dev.parent->driver->owner);

putdev_exit:
	put_device(&imgld->dev);

idle_exit:
	/*
	 * Note: imgld->remaining_size is left unmodified here to provide
	 * additional information on errors. It will be reinitialized when
	 * the next image load begins.
	 */
	vfree(imgld->data);
	imgld->data = NULL;
	fpga_image_prog_complete(imgld);
	eventfd_ctx_put(imgld->finished);
	imgld->finished = NULL;
}

static int fpga_image_load_ioctl_write(struct fpga_image_load *imgld,
				       unsigned long arg)
{
	struct fpga_image_write wb;
	unsigned long minsz;
	int ret;
	u8 *buf;

	if (imgld->driver_unload || imgld->progress != FPGA_IMAGE_PROG_IDLE)
		return -EBUSY;

	minsz = offsetofend(struct fpga_image_write, buf);
	if (copy_from_user(&wb, (void __user *)arg, minsz))
		return -EFAULT;

	if (wb.flags)
		return -EINVAL;

	if (!wb.size)
		return -EINVAL;

	if (wb.evtfd < 0)
		return -EINVAL;

	buf = vzalloc(wb.size);
	if (!buf)
		return -ENOMEM;

	if (copy_from_user(buf, u64_to_user_ptr(wb.buf), wb.size)) {
		ret = -EFAULT;
		goto exit_free;
	}

	imgld->finished = eventfd_ctx_fdget(wb.evtfd);
	if (IS_ERR(imgld->finished)) {
		ret = PTR_ERR(imgld->finished);
		imgld->finished = NULL;
		goto exit_free;
	}

	imgld->data = buf;
	imgld->remaining_size = wb.size;
	imgld->err_code = 0;
	imgld->progress = FPGA_IMAGE_PROG_STARTING;
	queue_work(system_long_wq, &imgld->work);

	return 0;

exit_free:
	vfree(buf);
	return ret;
}

static long fpga_image_load_ioctl(struct file *filp, unsigned int cmd,
				  unsigned long arg)
{
	struct fpga_image_load *imgld = filp->private_data;
	int ret = -ENOTTY;

	switch (cmd) {
	case FPGA_IMAGE_LOAD_WRITE:
		mutex_lock(&imgld->lock);
		ret = fpga_image_load_ioctl_write(imgld, arg);
		mutex_unlock(&imgld->lock);
		break;
	}

	return ret;
}

static int fpga_image_load_open(struct inode *inode, struct file *filp)
{
	struct fpga_image_load *imgld = container_of(inode->i_cdev,
						     struct fpga_image_load, cdev);

	if (atomic_cmpxchg(&imgld->opened, 0, 1))
		return -EBUSY;

	filp->private_data = imgld;

	return 0;
}

static int fpga_image_load_release(struct inode *inode, struct file *filp)
{
	struct fpga_image_load *imgld = filp->private_data;

	mutex_lock(&imgld->lock);
	if (imgld->progress == FPGA_IMAGE_PROG_IDLE) {
		mutex_unlock(&imgld->lock);
		goto close_exit;
	}

	mutex_unlock(&imgld->lock);
	flush_work(&imgld->work);

close_exit:
	atomic_set(&imgld->opened, 0);

	return 0;
}

static const struct file_operations fpga_image_load_fops = {
	.owner = THIS_MODULE,
	.open = fpga_image_load_open,
	.release = fpga_image_load_release,
	.unlocked_ioctl = fpga_image_load_ioctl,
};

/**
 * fpga_image_load_register - create and register an FPGA Image Load Device
 *
 * @parent: fpga image load device from pdev
 * @ops:   pointer to a structure of image load callback functions
 * @priv:   fpga image load private data
 *
 * Returns a struct fpga_image_load pointer on success, or ERR_PTR() on
 * error. The caller of this function is responsible for calling
 * fpga_image_load_unregister().
 */
struct fpga_image_load *
fpga_image_load_register(struct device *parent,
			 const struct fpga_image_load_ops *ops, void *priv)
{
	struct fpga_image_load *imgld;
	int ret;

	if (!ops || !ops->prepare || !ops->write || !ops->poll_complete) {
		dev_err(parent, "Attempt to register without all required ops\n");
		return ERR_PTR(-ENOMEM);
	}

	imgld = kzalloc(sizeof(*imgld), GFP_KERNEL);
	if (!imgld)
		return ERR_PTR(-ENOMEM);

	ret = xa_alloc(&fpga_image_load_xa, &imgld->dev.id, imgld, IMAGE_LOAD_XA_LIMIT,
		       GFP_KERNEL);
	if (ret)
		goto error_kfree;

	mutex_init(&imgld->lock);

	imgld->priv = priv;
	imgld->ops = ops;
	imgld->err_code = 0;
	imgld->progress = FPGA_IMAGE_PROG_IDLE;
	INIT_WORK(&imgld->work, fpga_image_do_load);

	imgld->dev.class = fpga_image_load_class;
	imgld->dev.parent = parent;
	imgld->dev.devt = MKDEV(MAJOR(fpga_image_devt), imgld->dev.id);

	ret = dev_set_name(&imgld->dev, "fpga_image_load%d", imgld->dev.id);
	if (ret) {
		dev_err(parent, "Failed to set device name: fpga_image_load%d\n",
			imgld->dev.id);
		goto error_device;
	}

	ret = device_register(&imgld->dev);
	if (ret) {
		put_device(&imgld->dev);
		return ERR_PTR(ret);
	}

	cdev_init(&imgld->cdev, &fpga_image_load_fops);
	imgld->cdev.owner = parent->driver->owner;
	cdev_set_parent(&imgld->cdev, &imgld->dev.kobj);

	ret = cdev_add(&imgld->cdev, imgld->dev.devt, 1);
	if (ret) {
		put_device(&imgld->dev);
		return ERR_PTR(ret);
	}

	return imgld;

error_device:
	xa_erase(&fpga_image_load_xa, imgld->dev.id);

error_kfree:
	kfree(imgld);

	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(fpga_image_load_register);

/**
 * fpga_image_load_unregister - unregister an FPGA image load device
 *
 * @imgld: pointer to struct fpga_image_load
 *
 * This function is intended for use in the parent driver's remove()
 * function. The driver_unload flag prevents new updates from starting
 * once the unregister process has begun.
 */
void fpga_image_load_unregister(struct fpga_image_load *imgld)
{
	mutex_lock(&imgld->lock);
	imgld->driver_unload = true;
	if (imgld->progress == FPGA_IMAGE_PROG_IDLE) {
		mutex_unlock(&imgld->lock);
		goto unregister;
	}

	mutex_unlock(&imgld->lock);
	flush_work(&imgld->work);

unregister:
	cdev_del(&imgld->cdev);
	device_unregister(&imgld->dev);
}
EXPORT_SYMBOL_GPL(fpga_image_load_unregister);

static void fpga_image_load_dev_release(struct device *dev)
{
	struct fpga_image_load *imgld = to_image_load(dev);

	xa_erase(&fpga_image_load_xa, imgld->dev.id);
	kfree(imgld);
}

static int __init fpga_image_load_class_init(void)
{
	int ret;
	pr_info("FPGA Image Load Framework\n");

	fpga_image_load_class = class_create(THIS_MODULE, "fpga_image_load");
	if (IS_ERR(fpga_image_load_class))
		return PTR_ERR(fpga_image_load_class);

	ret = alloc_chrdev_region(&fpga_image_devt, 0, MINORMASK,
				  "fpga_image_load");
	if (ret)
		goto exit_destroy_class;

	fpga_image_load_class->dev_release = fpga_image_load_dev_release;

	return 0;

exit_destroy_class:
	class_destroy(fpga_image_load_class);
	return ret;
}

static void __exit fpga_image_load_class_exit(void)
{
	unregister_chrdev_region(fpga_image_devt, MINORMASK);
	class_destroy(fpga_image_load_class);
	WARN_ON(!xa_empty(&fpga_image_load_xa));
}

MODULE_DESCRIPTION("FPGA Image Load Framework");
MODULE_LICENSE("GPL v2");

subsys_initcall(fpga_image_load_class_init);
module_exit(fpga_image_load_class_exit)
