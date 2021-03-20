// SPDX-License-Identifier: GPL-2.0
/*
 * FPGA Security Manager
 *
 * Copyright (C) 2019-2020 Intel Corporation, Inc.
 */

#include <linux/delay.h>
#include <linux/firmware.h>
#include <linux/fpga/fpga-sec-mgr.h>
#include <linux/idr.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

static DEFINE_IDA(fpga_sec_mgr_ida);
static struct class *fpga_sec_mgr_class;

struct fpga_sec_mgr_devres {
	struct fpga_sec_mgr *smgr;
};

#define WRITE_BLOCK_SIZE 0x4000	/* Update remaining_size every 0x4000 bytes */

#define to_sec_mgr(d) container_of(d, struct fpga_sec_mgr, dev)

static void update_progress(struct fpga_sec_mgr *smgr,
			    enum fpga_sec_prog new_progress)
{
	smgr->progress = new_progress;
	sysfs_notify(&smgr->dev.kobj, "update", "status");
}

static void set_error(struct fpga_sec_mgr *smgr, enum fpga_sec_err err_code)
{
	smgr->err_state = smgr->progress;
	smgr->err_code = err_code;
}

static void set_hw_errinfo(struct fpga_sec_mgr *smgr)
{
	if (smgr->sops->get_hw_errinfo)
		smgr->hw_errinfo = smgr->sops->get_hw_errinfo(smgr);
}

static void fpga_sec_dev_error(struct fpga_sec_mgr *smgr,
			       enum fpga_sec_err err_code)
{
	set_error(smgr, err_code);
	set_hw_errinfo(smgr);
	smgr->sops->cancel(smgr);
}

static int progress_transition(struct fpga_sec_mgr *smgr,
			       enum fpga_sec_prog new_progress)
{
	int ret = 0;

	mutex_lock(&smgr->lock);
	if (smgr->request_cancel) {
		set_error(smgr, FPGA_SEC_ERR_CANCELED);
		smgr->sops->cancel(smgr);
		ret = -ECANCELED;
	} else {
		update_progress(smgr, new_progress);
	}
	mutex_unlock(&smgr->lock);
	return ret;
}

static void progress_complete(struct fpga_sec_mgr *smgr)
{
	mutex_lock(&smgr->lock);
	update_progress(smgr, FPGA_SEC_PROG_IDLE);
	complete_all(&smgr->update_done);
	mutex_unlock(&smgr->lock);
}

static void fpga_sec_mgr_update(struct work_struct *work)
{
	u32 size, blk_size, offset = 0;
	struct fpga_sec_mgr *smgr;
	const struct firmware *fw;
	enum fpga_sec_err ret;

	smgr = container_of(work, struct fpga_sec_mgr, work);

	get_device(&smgr->dev);
	if (request_firmware(&fw, smgr->filename, &smgr->dev)) {
		set_error(smgr, FPGA_SEC_ERR_FILE_READ);
		goto idle_exit;
	}

	smgr->data = fw->data;
	smgr->remaining_size = fw->size;

	if (!try_module_get(smgr->dev.parent->driver->owner)) {
		set_error(smgr, FPGA_SEC_ERR_BUSY);
		goto release_fw_exit;
	}

	if (progress_transition(smgr, FPGA_SEC_PROG_PREPARING))
		goto modput_exit;

	ret = smgr->sops->prepare(smgr);
	if (ret != FPGA_SEC_ERR_NONE) {
		fpga_sec_dev_error(smgr, ret);
		goto modput_exit;
	}

	if (progress_transition(smgr, FPGA_SEC_PROG_WRITING))
		goto done;

	size = smgr->remaining_size;
	while (size && !smgr->request_cancel) {
		blk_size = min_t(u32, size, WRITE_BLOCK_SIZE);
		size -= blk_size;
		ret = smgr->sops->write_blk(smgr, offset, blk_size);
		if (ret != FPGA_SEC_ERR_NONE) {
			fpga_sec_dev_error(smgr, ret);
			goto done;
		}

		smgr->remaining_size = size;
		offset += blk_size;
	}

	if (progress_transition(smgr, FPGA_SEC_PROG_PROGRAMMING))
		goto done;

	ret = smgr->sops->poll_complete(smgr);
	if (ret != FPGA_SEC_ERR_NONE)
		fpga_sec_dev_error(smgr, ret);

done:
	if (smgr->sops->cleanup)
		smgr->sops->cleanup(smgr);

modput_exit:
	module_put(smgr->dev.parent->driver->owner);

release_fw_exit:
	smgr->data = NULL;
	release_firmware(fw);

idle_exit:
	/*
	 * Note: smgr->remaining_size is left unmodified here to
	 * provide additional information on errors. It will be
	 * reinitialized when the next secure update begins.
	 */
	kfree(smgr->filename);
	smgr->filename = NULL;
	put_device(&smgr->dev);
	progress_complete(smgr);
}

static const char * const sec_mgr_prog_str[] = {
	"idle",			/* FPGA_SEC_PROG_IDLE */
	"reading",		/* FPGA_SEC_PROG_READING */
	"preparing",		/* FPGA_SEC_PROG_PREPARING */
	"writing",		/* FPGA_SEC_PROG_WRITING */
	"programming"		/* FPGA_SEC_PROG_PROGRAMMING */
};

static const char * const sec_mgr_err_str[] = {
	"none",			/* FPGA_SEC_ERR_NONE */
	"hw-error",		/* FPGA_SEC_ERR_HW_ERROR */
	"timeout",		/* FPGA_SEC_ERR_TIMEOUT */
	"user-abort",		/* FPGA_SEC_ERR_CANCELED */
	"device-busy",		/* FPGA_SEC_ERR_BUSY */
	"invalid-file-size",	/* FPGA_SEC_ERR_INVALID_SIZE */
	"read-write-error",	/* FPGA_SEC_ERR_RW_ERROR */
	"flash-wearout",	/* FPGA_SEC_ERR_WEAROUT */
	"file-read-error"	/* FPGA_SEC_ERR_FILE_READ */
};

static const char *sec_progress(struct device *dev, enum fpga_sec_prog prog)
{
	const char *status = "unknown-status";

	if (prog < FPGA_SEC_PROG_MAX)
		status = sec_mgr_prog_str[prog];
	else
		dev_err(dev, "Invalid status during secure update: %d\n",
			prog);

	return status;
}

static const char *sec_error(struct device *dev, enum fpga_sec_err err_code)
{
	const char *error = "unknown-error";

	if (err_code < FPGA_SEC_ERR_MAX)
		error = sec_mgr_err_str[err_code];
	else
		dev_err(dev, "Invalid error code during secure update: %d\n",
			err_code);

	return error;
}

static ssize_t
status_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct fpga_sec_mgr *smgr = to_sec_mgr(dev);

	return sysfs_emit(buf, "%s\n", sec_progress(dev, smgr->progress));
}
static DEVICE_ATTR_RO(status);

static ssize_t
error_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct fpga_sec_mgr *smgr = to_sec_mgr(dev);
	int ret;

	mutex_lock(&smgr->lock);

	if (smgr->progress != FPGA_SEC_PROG_IDLE)
		ret = -EBUSY;
	else if (!smgr->err_code)
		ret = 0;
	else
		ret = sysfs_emit(buf, "%s:%s\n",
				 sec_progress(dev, smgr->err_state),
				 sec_error(dev, smgr->err_code));

	mutex_unlock(&smgr->lock);

	return ret;
}
static DEVICE_ATTR_RO(error);

static ssize_t
hw_errinfo_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct fpga_sec_mgr *smgr = to_sec_mgr(dev);
	int ret;

	mutex_lock(&smgr->lock);
	if (smgr->progress != FPGA_SEC_PROG_IDLE)
		ret = -EBUSY;
	else
		ret = sysfs_emit(buf, "0x%llx\n", smgr->hw_errinfo);
	mutex_unlock(&smgr->lock);

	return ret;
}
static DEVICE_ATTR_RO(hw_errinfo);

static ssize_t remaining_size_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	struct fpga_sec_mgr *smgr = to_sec_mgr(dev);

	return sysfs_emit(buf, "%u\n", smgr->remaining_size);
}
static DEVICE_ATTR_RO(remaining_size);

static ssize_t filename_store(struct device *dev, struct device_attribute *attr,
			      const char *buf, size_t count)
{
	struct fpga_sec_mgr *smgr = to_sec_mgr(dev);
	int ret = count;

	if (count == 0 || count >= PATH_MAX)
		return -EINVAL;

	mutex_lock(&smgr->lock);
	if (smgr->driver_unload || smgr->progress != FPGA_SEC_PROG_IDLE) {
		ret = -EBUSY;
		goto unlock_exit;
	}

	smgr->filename = kmemdup_nul(buf, count, GFP_KERNEL);
	if (!smgr->filename) {
		ret = -ENOMEM;
		goto unlock_exit;
	}

	smgr->err_code = FPGA_SEC_ERR_NONE;
	smgr->hw_errinfo = 0;
	smgr->request_cancel = false;
	smgr->progress = FPGA_SEC_PROG_READING;
	reinit_completion(&smgr->update_done);
	schedule_work(&smgr->work);

unlock_exit:
	mutex_unlock(&smgr->lock);
	return ret;
}
static DEVICE_ATTR_WO(filename);

static ssize_t cancel_store(struct device *dev, struct device_attribute *attr,
			    const char *buf, size_t count)
{
	struct fpga_sec_mgr *smgr = to_sec_mgr(dev);
	bool cancel;
	int ret = count;

	if (kstrtobool(buf, &cancel) || !cancel)
		return -EINVAL;

	mutex_lock(&smgr->lock);
	if (smgr->progress == FPGA_SEC_PROG_PROGRAMMING)
		ret = -EBUSY;
	else if (smgr->progress == FPGA_SEC_PROG_IDLE)
		ret = -ENODEV;
	else
		smgr->request_cancel = true;
	mutex_unlock(&smgr->lock);

	return ret;
}
static DEVICE_ATTR_WO(cancel);

static ssize_t available_images_show(struct device *dev,
				     struct device_attribute *attr, char *buf)
{
	struct fpga_sec_mgr *smgr = to_sec_mgr(dev);
	const struct image_load *hndlr;
	ssize_t count = 0;

	for (hndlr = smgr->sops->image_load; hndlr->name; hndlr++) {
		count += scnprintf(buf + count, PAGE_SIZE - count,
				   "%s ", hndlr->name);
	}

	buf[count - 1] = '\n';

	return count;
}
static DEVICE_ATTR_RO(available_images);

static ssize_t image_load_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct fpga_sec_mgr *smgr = to_sec_mgr(dev);
	const struct image_load *hndlr;
	int ret = -EINVAL;

	for (hndlr = smgr->sops->image_load; hndlr->name; hndlr++) {
		if (sysfs_streq(buf, hndlr->name)) {
			ret = hndlr->load_image(smgr);
			break;
		}
	}

	return ret ? : count;
}
static DEVICE_ATTR_WO(image_load);

static umode_t
sec_mgr_update_visible(struct kobject *kobj, struct attribute *attr, int n)
{
	struct fpga_sec_mgr *smgr = to_sec_mgr(kobj_to_dev(kobj));

	if (attr == &dev_attr_hw_errinfo.attr && !smgr->sops->get_hw_errinfo)
		return 0;

	if ((!smgr->sops->image_load || !smgr->sops->image_load->name) &&
	    (attr == &dev_attr_available_images.attr ||
	     attr == &dev_attr_image_load.attr))
		return 0;

	return attr->mode;
}

static struct attribute *sec_mgr_update_attrs[] = {
	&dev_attr_filename.attr,
	&dev_attr_cancel.attr,
	&dev_attr_status.attr,
	&dev_attr_error.attr,
	&dev_attr_remaining_size.attr,
	&dev_attr_hw_errinfo.attr,
	&dev_attr_available_images.attr,
	&dev_attr_image_load.attr,
	NULL,
};

static struct attribute_group sec_mgr_update_attr_group = {
	.name = "update",
	.attrs = sec_mgr_update_attrs,
	.is_visible = sec_mgr_update_visible,
};

static ssize_t name_show(struct device *dev,
			 struct device_attribute *attr, char *buf)
{
	struct fpga_sec_mgr *smgr = to_sec_mgr(dev);

	return sysfs_emit(buf, "%s\n", smgr->name);
}
static DEVICE_ATTR_RO(name);

static struct attribute *sec_mgr_attrs[] = {
	&dev_attr_name.attr,
	NULL,
};

static struct attribute_group sec_mgr_attr_group = {
	.attrs = sec_mgr_attrs,
};

static const struct attribute_group *fpga_sec_mgr_attr_groups[] = {
	&sec_mgr_attr_group,
	&sec_mgr_update_attr_group,
	NULL,
};

/**
 * fpga_sec_mgr_create - create and initialize an FPGA
 *			  security manager struct
 *
 * @dev:  fpga security manager device from pdev
 * @name: fpga security manager name
 * @sops: pointer to a structure of fpga callback functions
 * @priv: fpga security manager private data
 *
 * The caller of this function is responsible for freeing the struct
 * with ifpg_sec_mgr_free(). Using devm_fpga_sec_mgr_create() instead
 * is recommended.
 *
 * Return: pointer to struct fpga_sec_mgr or NULL
 */
struct fpga_sec_mgr *
fpga_sec_mgr_create(struct device *dev, const char *name,
		    const struct fpga_sec_mgr_ops *sops, void *priv)
{
	const struct image_load *hndlr;
	struct fpga_sec_mgr *smgr;
	int id, ret;

	if (!sops || !sops->cancel || !sops->prepare ||
	    !sops->write_blk || !sops->poll_complete) {
		dev_err(dev, "Attempt to register without required ops\n");
		return NULL;
	}

	if (sops->image_load) {
		for (hndlr = sops->image_load; hndlr->name; hndlr++) {
			if (!hndlr->load_image) {
				dev_err(dev, "No image_load trigger for %s\n",
					hndlr->name);
				return ERR_PTR(-EINVAL);
			}
		}
	}

	if (!name || !strlen(name)) {
		dev_err(dev, "Attempt to register with no name!\n");
		return NULL;
	}

	smgr = kzalloc(sizeof(*smgr), GFP_KERNEL);
	if (!smgr)
		return NULL;

	id = ida_simple_get(&fpga_sec_mgr_ida, 0, 0, GFP_KERNEL);
	if (id < 0)
		goto error_kfree;

	mutex_init(&smgr->lock);

	smgr->name = name;
	smgr->priv = priv;
	smgr->sops = sops;
	init_completion(&smgr->update_done);
	INIT_WORK(&smgr->work, fpga_sec_mgr_update);

	device_initialize(&smgr->dev);
	smgr->dev.class = fpga_sec_mgr_class;
	smgr->dev.parent = dev;
	smgr->dev.id = id;

	ret = dev_set_name(&smgr->dev, "fpga_sec%d", id);
	if (ret) {
		dev_err(dev, "Failed to set device name: fpga_sec%d\n", id);
		goto error_device;
	}

	return smgr;

error_device:
	ida_simple_remove(&fpga_sec_mgr_ida, id);

error_kfree:
	kfree(smgr);

	return NULL;
}
EXPORT_SYMBOL_GPL(fpga_sec_mgr_create);

/**
 * fpga_sec_mgr_free - free an FPGA security manager created
 *			with fpga_sec_mgr_create()
 *
 * @smgr:	FPGA security manager structure
 */
void fpga_sec_mgr_free(struct fpga_sec_mgr *smgr)
{
	ida_simple_remove(&fpga_sec_mgr_ida, smgr->dev.id);
	kfree(smgr);
}
EXPORT_SYMBOL_GPL(fpga_sec_mgr_free);

static void devm_fpga_sec_mgr_release(struct device *dev, void *res)
{
	struct fpga_sec_mgr_devres *dr = res;

	fpga_sec_mgr_free(dr->smgr);
}

/**
 * devm_fpga_sec_mgr_create - create and initialize an FPGA
 *			       security manager struct
 *
 * @dev:  fpga security manager device from pdev
 * @name: fpga security manager name
 * @sops: pointer to a structure of fpga callback functions
 * @priv: fpga security manager private data
 *
 * This function is intended for use in a FPGA Security manager
 * driver's probe function.  After the security manager driver creates
 * the fpga_sec_mgr struct with devm_fpga_sec_mgr_create(), it should
 * register it with devm_fpga_sec_mgr_register().
 * The fpga_sec_mgr struct allocated with this function will be freed
 * automatically on driver detach.
 *
 * Return: pointer to struct fpga_sec_mgr or NULL
 */
struct fpga_sec_mgr *
devm_fpga_sec_mgr_create(struct device *dev, const char *name,
			 const struct fpga_sec_mgr_ops *sops, void *priv)
{
	struct fpga_sec_mgr_devres *dr;

	dr = devres_alloc(devm_fpga_sec_mgr_release, sizeof(*dr), GFP_KERNEL);
	if (!dr)
		return NULL;

	dr->smgr = fpga_sec_mgr_create(dev, name, sops, priv);
	if (!dr->smgr) {
		devres_free(dr);
		return NULL;
	}

	devres_add(dev, dr);

	return dr->smgr;
}
EXPORT_SYMBOL_GPL(devm_fpga_sec_mgr_create);

/**
 * fpga_sec_mgr_register - register an FPGA security manager
 *
 * @smgr: fpga security manager struct
 *
 * Return: 0 on success, negative error code otherwise.
 */
int fpga_sec_mgr_register(struct fpga_sec_mgr *smgr)
{
	int ret;

	ret = device_add(&smgr->dev);
	if (ret)
		goto error_device;

	dev_info(&smgr->dev, "%s registered\n", smgr->name);

	return 0;

error_device:
	ida_simple_remove(&fpga_sec_mgr_ida, smgr->dev.id);

	return ret;
}
EXPORT_SYMBOL_GPL(fpga_sec_mgr_register);

/**
 * fpga_sec_mgr_unregister - unregister an FPGA security manager
 *
 * @mgr: fpga manager struct
 *
 * This function is intended for use in an FPGA security manager
 * driver's remove() function.
 *
 * For some devices, once the secure update has begun authentication
 * the hardware cannot be signaled to stop, and the driver will not
 * exit until the hardware signals completion.  This could be 30+
 * minutes of waiting. The driver_unload flag enableds a force-unload
 * of the driver (e.g. modprobe -r) by signaling the parent driver to
 * exit even if the hardware update is incomplete. The driver_unload
 * flag also prevents new updates from starting once the unregister
 * process has begun.
 */
void fpga_sec_mgr_unregister(struct fpga_sec_mgr *smgr)
{
	dev_info(&smgr->dev, "%s %s\n", __func__, smgr->name);

	mutex_lock(&smgr->lock);
	smgr->driver_unload = true;
	if (smgr->progress == FPGA_SEC_PROG_IDLE) {
		mutex_unlock(&smgr->lock);
		goto unregister;
	}

	if (smgr->progress != FPGA_SEC_PROG_PROGRAMMING)
		smgr->request_cancel = true;

	mutex_unlock(&smgr->lock);
	wait_for_completion(&smgr->update_done);

unregister:
	device_unregister(&smgr->dev);
}
EXPORT_SYMBOL_GPL(fpga_sec_mgr_unregister);

static int fpga_sec_mgr_devres_match(struct device *dev, void *res,
				     void *match_data)
{
	struct fpga_sec_mgr_devres *dr = res;

	return match_data == dr->smgr;
}

static void devm_fpga_sec_mgr_unregister(struct device *dev, void *res)
{
	struct fpga_sec_mgr_devres *dr = res;

	fpga_sec_mgr_unregister(dr->smgr);
}

/**
 * devm_fpga_sec_mgr_register - resource managed variant of
 *				fpga_sec_mgr_register()
 *
 * @dev: managing device for this FPGA security manager
 * @smgr: fpga security manager struct
 *
 * This is the devres variant of fpga_sec_mgr_register() for which the
 * unregister function will be called automatically when the managing
 * device is detached.
 */
int devm_fpga_sec_mgr_register(struct device *dev, struct fpga_sec_mgr *smgr)
{
	struct fpga_sec_mgr_devres *dr;
	int ret;

	/*
	 * Make sure that the struct fpga_sec_mgr * that is passed in is
	 * managed itself.
	 */
	if (WARN_ON(!devres_find(dev, devm_fpga_sec_mgr_release,
				 fpga_sec_mgr_devres_match, smgr)))
		return -EINVAL;

	dr = devres_alloc(devm_fpga_sec_mgr_unregister, sizeof(*dr), GFP_KERNEL);
	if (!dr)
		return -ENOMEM;

	ret = fpga_sec_mgr_register(smgr);
	if (ret) {
		devres_free(dr);
		return ret;
	}

	dr->smgr = smgr;
	devres_add(dev, dr);

	return 0;
}
EXPORT_SYMBOL_GPL(devm_fpga_sec_mgr_register);

static void fpga_sec_mgr_dev_release(struct device *dev)
{
}

static int __init fpga_sec_mgr_class_init(void)
{
	pr_info("FPGA Security Manager\n");

	fpga_sec_mgr_class = class_create(THIS_MODULE, "fpga_sec_mgr");
	if (IS_ERR(fpga_sec_mgr_class))
		return PTR_ERR(fpga_sec_mgr_class);

	fpga_sec_mgr_class->dev_groups = fpga_sec_mgr_attr_groups;
	fpga_sec_mgr_class->dev_release = fpga_sec_mgr_dev_release;

	return 0;
}

static void __exit fpga_sec_mgr_class_exit(void)
{
	class_destroy(fpga_sec_mgr_class);
	ida_destroy(&fpga_sec_mgr_ida);
}

MODULE_DESCRIPTION("FPGA Security Manager Driver");
MODULE_LICENSE("GPL v2");

subsys_initcall(fpga_sec_mgr_class_init);
module_exit(fpga_sec_mgr_class_exit)
