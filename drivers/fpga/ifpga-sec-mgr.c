// SPDX-License-Identifier: GPL-2.0
/*
 * Intel Security Manager for FPGA
 *
 * Copyright (C) 2019-2020 Intel Corporation, Inc.
 */

#include <linux/delay.h>
#include <linux/firmware.h>
#include <linux/fpga/ifpga-sec-mgr.h>
#include <linux/idr.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

static DEFINE_IDA(ifpga_sec_mgr_ida);
static struct class *ifpga_sec_mgr_class;

#define WRITE_BLOCK_SIZE	0x4000

static ssize_t show_root_entry_hash(struct ifpga_sec_mgr *imgr,
				    sysfs_reh_hndlr_t get_reh, char *buf)
{
	unsigned int i, hash_size = 0;
	int ret, cnt = 0;
	u8 *hash = NULL;

	ret = get_reh(imgr, &hash, &hash_size);
	if (ret)
		return ret;

	if (hash) {
		cnt += sprintf(buf, "0x");
		for (i = 0; i < hash_size; i++)
			cnt += sprintf(buf + cnt, "%02x", hash[i]);
		cnt += sprintf(buf + cnt, "\n");
		vfree(hash);
	} else {
		cnt = sprintf(buf, "hash not programmed\n");
	}
	return cnt;
}

#define to_sec_mgr(d) container_of(d, struct ifpga_sec_mgr, dev)

#define DEVICE_ATTR_SEC_CSK(_name) \
	static ssize_t _name##_canceled_csks_show(struct device *dev, \
			    struct device_attribute *attr, char *buf) \
	{ \
		struct ifpga_sec_mgr *imgr = to_sec_mgr(dev); \
		unsigned long *csk_map = NULL; \
		unsigned int cnt, nbits = 0; \
		int ret; \
		\
		ret = imgr->iops->_name##_canceled_csks(imgr, &csk_map, \
						       &nbits); \
		if (ret) \
			return ret; \
		\
		cnt = bitmap_print_to_pagebuf(1, buf, csk_map, nbits); \
		vfree(csk_map); \
		return cnt; \
	} \
	static DEVICE_ATTR_RO(_name##_canceled_csks)

#define DEVICE_ATTR_SEC_ROOT_ENTRY_HASH(_name) \
	static ssize_t _name##_root_entry_hash_show(struct device *dev, \
					     struct device_attribute *attr, \
					     char *buf) \
	{ \
		struct ifpga_sec_mgr *imgr = to_sec_mgr(dev); \
		return show_root_entry_hash(imgr, \
		       imgr->iops->_name##_root_entry_hash, buf); \
	} \
	static DEVICE_ATTR_RO(_name##_root_entry_hash)

#define DEVICE_ATTR_SEC_FLASH_CNT(_name) \
	static ssize_t _name##_flash_count_show(struct device *dev, \
			    struct device_attribute *attr, char *buf) \
	{ \
		struct ifpga_sec_mgr *imgr = to_sec_mgr(dev); \
		int cnt = imgr->iops->_name##_flash_count(imgr); \
		return cnt < 0 ? cnt : sprintf(buf, "%d\n", cnt); \
	} \
	static DEVICE_ATTR_RO(_name##_flash_count)

DEVICE_ATTR_SEC_ROOT_ENTRY_HASH(sr);
DEVICE_ATTR_SEC_ROOT_ENTRY_HASH(pr);
DEVICE_ATTR_SEC_ROOT_ENTRY_HASH(bmc);
DEVICE_ATTR_SEC_FLASH_CNT(user);
DEVICE_ATTR_SEC_FLASH_CNT(bmc);
DEVICE_ATTR_SEC_CSK(sr);
DEVICE_ATTR_SEC_CSK(pr);
DEVICE_ATTR_SEC_CSK(bmc);

static struct attribute *sec_mgr_security_attrs[] = {
	&dev_attr_user_flash_count.attr,
	&dev_attr_bmc_flash_count.attr,
	&dev_attr_bmc_root_entry_hash.attr,
	&dev_attr_sr_root_entry_hash.attr,
	&dev_attr_pr_root_entry_hash.attr,
	&dev_attr_sr_canceled_csks.attr,
	&dev_attr_pr_canceled_csks.attr,
	&dev_attr_bmc_canceled_csks.attr,
	NULL,
};

static void ifpga_sec_set_error(struct ifpga_sec_mgr *imgr, int err_code)
{
	mutex_lock(&imgr->lock);
	imgr->err_state = imgr->progress;
	imgr->err_code = err_code;
	mutex_unlock(&imgr->lock);
}

static int ifpga_sec_mgr_do_cancel(struct ifpga_sec_mgr *imgr)
{
	int ret;

	if (imgr->request_cancel) {
		ret = imgr->iops->cancel(imgr);
		if (!ret) {
			ifpga_sec_set_error(imgr, -ECANCELED);
			return 1;
		}
	}
	return 0;
}

static void
ifpga_sec_mgr_update_progress(struct ifpga_sec_mgr *imgr, u32 progress)
{
	mutex_lock(&imgr->lock);
	imgr->progress = progress;
	sysfs_notify(&imgr->dev.kobj, "update", "status");
	mutex_unlock(&imgr->lock);
}

static void ifpga_sec_mgr_update(struct work_struct *work)
{
	u32 size, blk_size, offset = 0;
	struct ifpga_sec_mgr *imgr;
	const struct firmware *fw;
	int ret;

	imgr = container_of(work, struct ifpga_sec_mgr, work);

	get_device(&imgr->dev);
	ret = request_firmware(&fw, imgr->filename, &imgr->dev);
	if (ret) {
		ifpga_sec_set_error(imgr, -ENOENT);
		goto idle_exit;
	}

	if (imgr->request_cancel) {
		ifpga_sec_set_error(imgr, -ECANCELED);
		goto release_fw_exit;
	}

	imgr->data = fw->data;
	imgr->remaining_size = fw->size;

	ifpga_sec_mgr_update_progress(imgr, IFPGA_SEC_PROG_PREPARING);
	ret = imgr->iops->prepare(imgr);
	if (ret) {
		ifpga_sec_set_error(imgr, ret);
		imgr->iops->cancel(imgr);
		goto release_fw_exit;
	}

	if (ifpga_sec_mgr_do_cancel(imgr))
		goto done;

	ifpga_sec_mgr_update_progress(imgr, IFPGA_SEC_PROG_WRITING);
	size = imgr->remaining_size;
	while (size) {
		blk_size = min_t(u32, size, WRITE_BLOCK_SIZE);
		size -= blk_size;
		ret = imgr->iops->write_blk(imgr, offset, blk_size);
		if (ret) {
			ifpga_sec_set_error(imgr, ret);
			imgr->iops->cancel(imgr);
			goto done;
		}

		imgr->remaining_size = size;
		if (ifpga_sec_mgr_do_cancel(imgr))
			goto done;

		offset += blk_size;
	}

	ifpga_sec_mgr_update_progress(imgr, IFPGA_SEC_PROG_PROGRAMMING);
	ret = imgr->iops->poll_complete(imgr);
	if (ret)
		ifpga_sec_set_error(imgr, ret);

done:
	if (imgr->iops->cleanup)
		imgr->iops->cleanup(imgr);

release_fw_exit:
	imgr->data = NULL;
	release_firmware(fw);

idle_exit:
	ifpga_sec_mgr_update_progress(imgr, IFPGA_SEC_PROG_IDLE);
	kfree(imgr->filename);
	imgr->filename = NULL;
	put_device(&imgr->dev);
}

#define check_attr(attribute, _name) \
	((attribute) == &dev_attr_##_name.attr && imgr->iops->_name)

static umode_t sec_mgr_visible(struct kobject *kobj,
			       struct attribute *attr, int n)
{
	struct ifpga_sec_mgr *imgr = to_sec_mgr(kobj_to_dev(kobj));

	if (check_attr(attr, user_flash_count) ||
	    check_attr(attr, bmc_flash_count) ||
	    check_attr(attr, bmc_root_entry_hash) ||
	    check_attr(attr, sr_root_entry_hash) ||
	    check_attr(attr, pr_root_entry_hash) ||
	    check_attr(attr, sr_canceled_csks) ||
	    check_attr(attr, pr_canceled_csks) ||
	    check_attr(attr, bmc_canceled_csks))
		return attr->mode;

	return 0;
}

static struct attribute_group sec_mgr_security_attr_group = {
	.name = "security",
	.attrs = sec_mgr_security_attrs,
	.is_visible = sec_mgr_visible,
};

static const char * const sec_mgr_prog_str[] = {
	"idle",			/* IFPGA_SEC_PROG_IDLE */
	"read_file",		/* IFPGA_SEC_PROG_READ_FILE */
	"preparing",		/* IFPGA_SEC_PROG_PREPARING */
	"writing",		/* IFPGA_SEC_PROG_WRITING */
	"programming",		/* IFPGA_SEC_PROG_PROGRAMMING */
};

static const struct sec_mgr_error {
	const int	err_code;
	const char	*err_str;
} sec_mgr_errors[] = {
	{ -EINVAL,    "hw-error"},
	{ -ETIMEDOUT, "timeout"},
	{ -ECANCELED, "user-abort"},
	{ -EBUSY,     "device-busy"},
	{ -EFBIG,     "invalid-file-size"},
	{ -EIO,       "read-write-error"},
	{ -EAGAIN,    "flash-wearout"},
	{ -ENOENT,    "file-read-error"}
};

static const char *sec_progress(struct ifpga_sec_mgr *imgr)
{
	return (imgr->progress < IFPGA_SEC_PROG_MAX) ?
		sec_mgr_prog_str[imgr->progress] : "unknown-status";
}

static ssize_t
status_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%s\n", sec_progress(to_sec_mgr(dev)));
}
static DEVICE_ATTR_RO(status);

static ssize_t
error_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	const char *prog_str, *err_str = "unknown-error";
	struct ifpga_sec_mgr *imgr = to_sec_mgr(dev);
	int err_code;
	ssize_t i;

	if (!imgr->err_code)
		return 0;

	mutex_lock(&imgr->lock);
	err_code = imgr->err_code;
	prog_str = sec_progress(imgr);
	mutex_unlock(&imgr->lock);

	for (i = 0; i < ARRAY_SIZE(sec_mgr_errors); i++) {
		if (sec_mgr_errors[i].err_code == err_code) {
			err_str = sec_mgr_errors[i].err_str;
			break;
		}
	}
	return sprintf(buf, "%s:%s\n", prog_str, err_str);
}
static DEVICE_ATTR_RO(error);

static ssize_t remaining_size_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	struct ifpga_sec_mgr *imgr = to_sec_mgr(dev);

	return sprintf(buf, "%u\n", imgr->remaining_size);
}
static DEVICE_ATTR_RO(remaining_size);

static ssize_t filename_store(struct device *dev, struct device_attribute *attr,
			      const char *buf, size_t count)
{
	struct ifpga_sec_mgr *imgr = to_sec_mgr(dev);
	int ret = 0;

	if (count == 0 || count >= PATH_MAX)
		return -EINVAL;

	mutex_lock(&imgr->lock);
	if (imgr->driver_unload || imgr->progress != IFPGA_SEC_PROG_IDLE) {
		ret = -EBUSY;
		goto unlock_exit;
	}

	imgr->filename = kstrndup(buf, PATH_MAX - 1, GFP_KERNEL);
	if (!imgr->filename) {
		ret = -ENOMEM;
		goto unlock_exit;
	}

	if (imgr->filename[strlen(imgr->filename) - 1] == '\n')
		imgr->filename[strlen(imgr->filename) - 1] = '\0';

	imgr->err_code = 0;
	imgr->request_cancel = false;
	imgr->progress = IFPGA_SEC_PROG_READ_FILE;
	schedule_work(&imgr->work);

unlock_exit:
	mutex_unlock(&imgr->lock);
	return ret ? : count;
}
static DEVICE_ATTR_WO(filename);

static ssize_t cancel_store(struct device *dev, struct device_attribute *attr,
			    const char *buf, size_t count)
{
	struct ifpga_sec_mgr *imgr = to_sec_mgr(dev);
	bool cancel;
	int ret = 0;

	if (kstrtobool(buf, &cancel) || !cancel)
		return -EINVAL;

	mutex_lock(&imgr->lock);
	if (imgr->progress == IFPGA_SEC_PROG_READ_FILE ||
	    imgr->progress == IFPGA_SEC_PROG_PREPARING ||
	    imgr->progress == IFPGA_SEC_PROG_WRITING)
		imgr->request_cancel = true;
	else if (imgr->progress == IFPGA_SEC_PROG_PROGRAMMING)
		ret = -EBUSY;
	mutex_unlock(&imgr->lock);

	return ret ? : count;
}
static DEVICE_ATTR_WO(cancel);

static struct attribute *sec_mgr_update_attrs[] = {
	&dev_attr_filename.attr,
	&dev_attr_cancel.attr,
	&dev_attr_status.attr,
	&dev_attr_error.attr,
	&dev_attr_remaining_size.attr,
	NULL,
};

static struct attribute_group sec_mgr_update_attr_group = {
	.name = "update",
	.attrs = sec_mgr_update_attrs,
};

static const struct attribute_group *ifpga_sec_mgr_attr_groups[] = {
	&sec_mgr_security_attr_group,
	&sec_mgr_update_attr_group,
	NULL,
};

/**
 * ifpga_sec_mgr_create - create and initialize a IFPGA security manager struct
 *
 * @dev:  create ifpga security manager device from pdev
 * @name: ifpga security manager name
 * @iops: pointer to a structure of ifpga callback functions
 * @priv: ifpga security manager private data
 *
 * The caller of this function is responsible for freeing the struct with
 * ifpga_sec_mgr_free().
 *
 * Return: pointer to struct ifpga_sec_mgr or NULL
 */
struct ifpga_sec_mgr *
ifpga_sec_mgr_create(struct device *dev, const char *name,
		     const struct ifpga_sec_mgr_ops *iops, void *priv)
{
	struct ifpga_sec_mgr *imgr;
	int id, ret;

	if (!iops || !iops->cancel || !iops->prepare ||
	    !iops->write_blk || !iops->poll_complete) {
		dev_err(dev, "Attempt to register without ifpga_sec_mgr_ops\n");
		return NULL;
	}

	if (!name || !strlen(name)) {
		dev_err(dev, "Attempt to register with no name!\n");
		return NULL;
	}

	imgr = kzalloc(sizeof(*imgr), GFP_KERNEL);
	if (!imgr)
		return NULL;

	id = ida_simple_get(&ifpga_sec_mgr_ida, 0, 0, GFP_KERNEL);
	if (id < 0) {
		ret = id;
		goto exit_kfree;
	}

	imgr->name = name;
	imgr->priv = priv;
	imgr->iops = iops;
	INIT_WORK(&imgr->work, ifpga_sec_mgr_update);

	device_initialize(&imgr->dev);
	imgr->dev.class = ifpga_sec_mgr_class;
	imgr->dev.parent = dev;
	imgr->dev.id = id;

	if (dev_set_name(&imgr->dev, "ifpga_sec%d", id)) {
		dev_err(dev, "Failed to set device name: ifpga_sec%d\n", id);
		goto exit_remove_ida;
	}

	mutex_init(&imgr->lock);
	return imgr;

exit_remove_ida:
	ida_simple_remove(&ifpga_sec_mgr_ida, id);
exit_kfree:
	kfree(imgr);

	return NULL;
}
EXPORT_SYMBOL_GPL(ifpga_sec_mgr_create);

/**
 * ifpga_sec_mgr_free - free a security mgr created with ifpga_sec_mgr_create()
 * @imgr: ifpga security manager struct
 */
void ifpga_sec_mgr_free(struct ifpga_sec_mgr *imgr)
{
	mutex_destroy(&imgr->lock);
	ida_simple_remove(&ifpga_sec_mgr_ida, imgr->dev.id);
	kfree(imgr);
}
EXPORT_SYMBOL_GPL(ifpga_sec_mgr_free);

/**
 * ifpga_sec_mgr_register - register a IFPGA security manager
 *
 * @mgr: ifpga security manager struct
 *
 * Return: 0 on success, negative error code otherwise.
 */
int ifpga_sec_mgr_register(struct ifpga_sec_mgr *imgr)
{
	int ret;

	ret = device_add(&imgr->dev);
	if (!ret)
		dev_info(&imgr->dev, "%s registered\n", imgr->name);

	return ret;
}
EXPORT_SYMBOL_GPL(ifpga_sec_mgr_register);

/**
 * ifpga_sec_mgr_unregister - unregister a IFPGA security manager
 *
 * @mgr: fpga manager struct
 *
 * This function is intended for use in a IFPGA security manager
 * driver's remove() function.
 */
void ifpga_sec_mgr_unregister(struct ifpga_sec_mgr *imgr)
{
	dev_info(&imgr->dev, "%s %s\n", __func__, imgr->name);

	mutex_lock(&imgr->lock);
	imgr->driver_unload = true;
	if (imgr->progress != IFPGA_SEC_PROG_IDLE) {
		imgr->request_cancel = true;
		dev_info(&imgr->dev, "%s waiting on secure update\n",
			 __func__);
		do {
			mutex_unlock(&imgr->lock);
			msleep(1000);
			mutex_lock(&imgr->lock);
		} while (imgr->progress != IFPGA_SEC_PROG_IDLE);
	}
	mutex_unlock(&imgr->lock);
	device_unregister(&imgr->dev);
}
EXPORT_SYMBOL_GPL(ifpga_sec_mgr_unregister);

static void ifpga_sec_mgr_dev_release(struct device *dev)
{
	ifpga_sec_mgr_free(to_sec_mgr(dev));
}

static int __init ifpga_sec_mgr_class_init(void)
{
	pr_info("Intel FPGA Security Manager\n");

	ifpga_sec_mgr_class = class_create(THIS_MODULE, "ifpga_sec_mgr");
	if (IS_ERR(ifpga_sec_mgr_class))
		return PTR_ERR(ifpga_sec_mgr_class);

	ifpga_sec_mgr_class->dev_groups = ifpga_sec_mgr_attr_groups;
	ifpga_sec_mgr_class->dev_release = ifpga_sec_mgr_dev_release;

	return 0;
}

static void __exit ifpga_sec_mgr_class_exit(void)
{
	class_destroy(ifpga_sec_mgr_class);
	ida_destroy(&ifpga_sec_mgr_ida);
}

MODULE_DESCRIPTION("Intel FPGA Security Manager Driver");
MODULE_LICENSE("GPL v2");

subsys_initcall(ifpga_sec_mgr_class_init);
module_exit(ifpga_sec_mgr_class_exit)
