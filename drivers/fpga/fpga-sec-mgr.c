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

static ssize_t
show_canceled_csk(struct fpga_sec_mgr *smgr,
		  int (*get_csk)(struct fpga_sec_mgr *smgr,
				 unsigned long *csk_map, unsigned int nbits),
		  int (*get_csk_nbits)(struct fpga_sec_mgr *smgr),
		  char *buf)
{
	unsigned long *csk_map = NULL;
	unsigned int nbits;
	int ret;

	ret = get_csk_nbits(smgr);
	if (ret < 0)
		return ret;

	nbits = (unsigned int)ret;
	csk_map = vmalloc(sizeof(unsigned long) * BITS_TO_LONGS(nbits));
	if (!csk_map)
		return -ENOMEM;

	ret = get_csk(smgr, csk_map, nbits);
	if (ret)
		goto vfree_exit;

	ret = bitmap_print_to_pagebuf(1, buf, csk_map, nbits);

vfree_exit:
	vfree(csk_map);
	return ret;
}

static ssize_t
show_root_entry_hash(struct fpga_sec_mgr *smgr,
		     int (*get_reh)(struct fpga_sec_mgr *smgr, u8 *hash,
				    unsigned int size),
		     int (*get_reh_size)(struct fpga_sec_mgr *smgr),
		     char *buf)
{
	int size, i, cnt, ret;
	u8 *hash;

	ret = get_reh_size(smgr);
	if (ret < 0)
		return ret;
	else if (!ret)
		return sysfs_emit(buf, "hash not programmed\n");

	size = ret;
	hash = vmalloc(size);
	if (!hash)
		return -ENOMEM;

	ret = get_reh(smgr, hash, size);
	if (ret)
		goto vfree_exit;

	cnt = sprintf(buf, "0x");
	for (i = 0; i < size; i++)
		cnt += sprintf(buf + cnt, "%02x", hash[i]);
	cnt += sprintf(buf + cnt, "\n");

vfree_exit:
	vfree(hash);
	return ret ? : cnt;
}

#define DEVICE_ATTR_SEC_CSK(_name) \
static ssize_t _name##_canceled_csks_show(struct device *dev, \
					  struct device_attribute *attr, \
					  char *buf) \
{ \
	struct fpga_sec_mgr *smgr = to_sec_mgr(dev); \
	return show_canceled_csk(smgr, \
	       smgr->sops->_name##_canceled_csks, \
	       smgr->sops->_name##_canceled_csk_nbits, buf); \
} \
static DEVICE_ATTR_RO(_name##_canceled_csks)

#define DEVICE_ATTR_SEC_ROOT_ENTRY_HASH(_name) \
static ssize_t _name##_root_entry_hash_show(struct device *dev, \
				     struct device_attribute *attr, \
				     char *buf) \
{ \
	struct fpga_sec_mgr *smgr = to_sec_mgr(dev); \
	return show_root_entry_hash(smgr, \
	       smgr->sops->_name##_root_entry_hash, \
	       smgr->sops->_name##_reh_size, buf); \
} \
static DEVICE_ATTR_RO(_name##_root_entry_hash)

static ssize_t user_flash_count_show(struct device *dev,
				     struct device_attribute *attr, char *buf)
{
	struct fpga_sec_mgr *smgr = to_sec_mgr(dev);
	int cnt = smgr->sops->user_flash_count(smgr);

	return cnt < 0 ? cnt : sysfs_emit(buf, "%u\n", cnt);
}
static DEVICE_ATTR_RO(user_flash_count);

DEVICE_ATTR_SEC_ROOT_ENTRY_HASH(sr);
DEVICE_ATTR_SEC_ROOT_ENTRY_HASH(pr);
DEVICE_ATTR_SEC_ROOT_ENTRY_HASH(bmc);
DEVICE_ATTR_SEC_CSK(sr);
DEVICE_ATTR_SEC_CSK(pr);
DEVICE_ATTR_SEC_CSK(bmc);

static struct attribute *sec_mgr_security_attrs[] = {
	&dev_attr_user_flash_count.attr,
	&dev_attr_bmc_root_entry_hash.attr,
	&dev_attr_sr_root_entry_hash.attr,
	&dev_attr_pr_root_entry_hash.attr,
	&dev_attr_sr_canceled_csks.attr,
	&dev_attr_pr_canceled_csks.attr,
	&dev_attr_bmc_canceled_csks.attr,
	NULL,
};

static void update_progress(struct fpga_sec_mgr *smgr,
			    enum fpga_sec_prog new_progress)
{
	smgr->progress = new_progress;
	sysfs_notify(&smgr->dev.kobj, "update", "status");
}

static void fpga_sec_dev_error(struct fpga_sec_mgr *smgr,
			       enum fpga_sec_err err_code)
{
	smgr->err_code = err_code;
	smgr->sops->cancel(smgr);
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
		smgr->err_code = FPGA_SEC_ERR_FILE_READ;
		goto idle_exit;
	}

	smgr->data = fw->data;
	smgr->remaining_size = fw->size;

	if (!try_module_get(smgr->dev.parent->driver->owner)) {
		smgr->err_code = FPGA_SEC_ERR_BUSY;
		goto release_fw_exit;
	}

	update_progress(smgr, FPGA_SEC_PROG_PREPARING);
	ret = smgr->sops->prepare(smgr);
	if (ret != FPGA_SEC_ERR_NONE) {
		fpga_sec_dev_error(smgr, ret);
		goto modput_exit;
	}

	update_progress(smgr, FPGA_SEC_PROG_WRITING);
	size = smgr->remaining_size;
	while (size) {
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

	update_progress(smgr, FPGA_SEC_PROG_PROGRAMMING);
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

#define check_attr(attribute, _name) \
	((attribute) == &dev_attr_##_name.attr && smgr->sops->_name)

static umode_t sec_mgr_visible(struct kobject *kobj,
			       struct attribute *attr, int n)
{
	struct fpga_sec_mgr *smgr = to_sec_mgr(kobj_to_dev(kobj));

	/*
	 * Only display optional sysfs attributes if a
	 * corresponding handler is provided
	 */
	if (check_attr(attr, user_flash_count) ||
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
	"idle",			/* FPGA_SEC_PROG_IDLE */
	"reading",		/* FPGA_SEC_PROG_READING */
	"preparing",		/* FPGA_SEC_PROG_PREPARING */
	"writing",		/* FPGA_SEC_PROG_WRITING */
	"programming"		/* FPGA_SEC_PROG_PROGRAMMING */
};

static ssize_t
status_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct fpga_sec_mgr *smgr = to_sec_mgr(dev);
	const char *status = "unknown-status";
	enum fpga_sec_prog progress;

	progress = smgr->progress;
	if (progress < FPGA_SEC_PROG_MAX)
		status = sec_mgr_prog_str[progress];
	else
		dev_err(dev, "Invalid status during secure update: %d\n",
			progress);

	return sysfs_emit(buf, "%s\n", status);
}
static DEVICE_ATTR_RO(status);

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

	smgr->filename = kstrndup(buf, count - 1, GFP_KERNEL);
	if (!smgr->filename) {
		ret = -ENOMEM;
		goto unlock_exit;
	}

	smgr->err_code = FPGA_SEC_ERR_NONE;
	smgr->progress = FPGA_SEC_PROG_READING;
	reinit_completion(&smgr->update_done);
	schedule_work(&smgr->work);

unlock_exit:
	mutex_unlock(&smgr->lock);
	return ret;
}
static DEVICE_ATTR_WO(filename);

static struct attribute *sec_mgr_update_attrs[] = {
	&dev_attr_filename.attr,
	&dev_attr_status.attr,
	NULL,
};

static struct attribute_group sec_mgr_update_attr_group = {
	.name = "update",
	.attrs = sec_mgr_update_attrs,
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
	&sec_mgr_security_attr_group,
	&sec_mgr_update_attr_group,
	NULL,
};

static bool check_sysfs_handler(struct device *dev,
				void *sysfs_handler, void *size_handler,
				const char *sysfs_handler_name,
				const char *size_handler_name)
{
	/*
	 * sysfs_handler and size_handler must either both be
	 * defined or both be NULL.
	 */
	if (sysfs_handler && !size_handler) {
		dev_err(dev, "%s registered without %s\n",
			sysfs_handler_name, size_handler_name);
		return false;
	} else if (!sysfs_handler && size_handler) {
		dev_err(dev, "%s registered without %s\n",
			size_handler_name, sysfs_handler_name);
		return false;
	}
	return true;
}

#define check_reh_handler(_dev, _sops, _name) \
	check_sysfs_handler(_dev, (_sops)->_name##_root_entry_hash, \
			    (_sops)->_name##_reh_size, \
			    __stringify(_name##_root_entry_hash), \
			    __stringify(_name##_reh_size))

#define check_csk_handler(_dev, _sops, _name) \
	check_sysfs_handler(_dev, (_sops)->_name##_canceled_csks, \
			    (_sops)->_name##_canceled_csk_nbits, \
			    __stringify(_name##_canceled_csks), \
			    __stringify(_name##_canceled_csk_nbits))

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
	struct fpga_sec_mgr *smgr;
	int id, ret;

	if (!sops || !sops->cancel || !sops->prepare ||
	    !sops->write_blk || !sops->poll_complete) {
		dev_err(dev, "Attempt to register without required ops\n");
		return NULL;
	}

	if (!check_reh_handler(dev, sops, bmc) ||
	    !check_reh_handler(dev, sops, sr) ||
	    !check_reh_handler(dev, sops, pr) ||
	    !check_csk_handler(dev, sops, bmc) ||
	    !check_csk_handler(dev, sops, sr) ||
	    !check_csk_handler(dev, sops, pr)) {
		return NULL;
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
