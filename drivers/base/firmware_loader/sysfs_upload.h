/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __FIRMWARE_UPLOAD_H
#define __FIRMWARE_UPLOAD_H

#include <linux/device.h>

/**
 * enum fw_upload_prog - firmware upload progress codes
 * @FW_UPLOAD_PROG_IDLE: there is no firmware upload in progress
 * @FW_UPLOAD_PROG_RECEIVING: worker thread is receiving firmware data
 * @FW_UPLOAD_PROG_PREPARING: target device is preparing for firmware upload
 * @FW_UPLOAD_PROG_TRANSFERRING: data is being copied to the device
 * @FW_UPLOAD_PROG_PROGRAMMING: device is performing the firmware update
 * @FW_UPLOAD_PROG_MAX: Maximum progress code marker
 */
enum fw_upload_prog {
	FW_UPLOAD_PROG_IDLE,
	FW_UPLOAD_PROG_RECEIVING,
	FW_UPLOAD_PROG_PREPARING,
	FW_UPLOAD_PROG_TRANSFERRING,
	FW_UPLOAD_PROG_PROGRAMMING,
	FW_UPLOAD_PROG_MAX
};

struct fw_upload_priv {
	struct fw_upload *fw_upload;
	struct module *module;
	const char *name;
	const struct fw_upload_ops *ops;
	struct mutex lock;		  /* protect data structure contents */
	struct work_struct work;
	const u8 *data;			  /* pointer to update data */
	u32 remaining_size;		  /* size remaining to transfer */
	enum fw_upload_prog progress;
	enum fw_upload_prog err_progress; /* progress at time of failure */
	enum fw_upload_err err_code;	  /* security manager error code */
};

#ifdef CONFIG_FW_UPLOAD
extern struct device_attribute dev_attr_status;
extern struct device_attribute dev_attr_error;
extern struct device_attribute dev_attr_cancel;
extern struct device_attribute dev_attr_remaining_size;

int fw_upload_start(struct fw_sysfs *fw_sysfs);
umode_t fw_upload_is_visible(struct kobject *kobj, struct attribute *attr, int n);
#else
static inline int fw_upload_start(struct fw_sysfs *fw_sysfs)
{
	return 0;
}
#endif

#endif /* __FIRMWARE_UPLOAD_H */
